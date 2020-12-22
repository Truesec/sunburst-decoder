Param(
    [string]$DnsQuery = "",
    [string]$DnsQueryFile,
    [string]$OutFileCsv,
    [switch]$MatchSystemGuid,
    [switch]$NoOutputOnScreen,
    [string]$Mac = "",
    [string]$Domain = "",
    [string]$MachineGuid = ""   
)

function GetHostIdFromParams {
    param (
        [string]$Mac,
        [string]$Domain,
        [string]$Guid
    )

    $hash64 = [System.Byte[]]::CreateInstance([System.Byte],8)
    [System.Array]::Clear($hash64,0,$hash64.Length)

    $composed = "$Mac$Domain$Guid"

    $md5 = [System.Security.Cryptography.MD5]::Create()

    $bytes = [System.Text.Encoding]::ASCII.GetBytes($composed);
    $hash = $md5.ComputeHash($bytes)

    for ($i = 0 ; $i -lt $hash.Length ; $i++)
    {
        $hash64[$i % $hash64.Length] = $hash64[$i % $hash64.Length] -bxor $hash[$i]
    }

    $hostid = [System.BitConverter]::ToString($hash64).Replace("-", "");

    return $hostid
}


$SunburstDefinition = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


/// <summary>
/// SUNBURST Domain Decoder, written by Erik Hjelmvik, Netresec
/// 
/// License: Creative Commons Attribution license "CC-BY", which implies you are free:
/// * to Share : to copy, distribute and transmit the work
/// * to Remix : to adapt the work
/// Under the following conditions:
/// * Attribution : You must attribute the work to "Erik Hjelmvik, Netresec"
///   and documentation should include a link to this blog post:
///   https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS
/// </summary>
public class SunburstDomainDecoder
{
    /// <summary>
    /// OrionImprovementBusinessLayer.ZipHelper.Unzip("Kyo0Ti9OzCkxKzXMrEyryi8wNTdKMbFMyquwSC7LzU4tz8gCAA==");
    /// </summary>
    private const string SUBSTITUTION_CIPHER_ALPHABET = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj";
    private readonly Dictionary<char, char> reverseSubstitutionCipherDictionary;

    /// <summary>
    /// OrionImprovementBusinessLayer.ZipHelper.Unzip("M4jX1QMA");
    /// </summary>
    private const string SPECIAL_CHARS = "0_-.";

    /// <summary>
    /// OrionImprovementBusinessLayer.ZipHelper.Unzip("K8gwSs1MyzfOMy0tSTfMskixNCksKkvKzTYoTswxN0sGAA==");
    /// </summary>
    private const string BASE32_ALPHABET = "ph2eifo3n5utg1j8d94qrvbmk0sal76c";
    private readonly Dictionary<char, uint> reverseBase32Dictionary;

    private static IEnumerable<string> StdInLines()
    {
        string domain = Console.In.ReadLine().Trim();
        while (domain != null)
        {
            if (domain.Length > 0)
                yield return domain;
            domain = Console.In.ReadLine().Trim();
        }
    }

    public SunburstDomainDecoder()
    {
        //preparde dictionaries for faster lookups (Array.IndexOf is slow)
        this.reverseSubstitutionCipherDictionary = new Dictionary<char, char>(SUBSTITUTION_CIPHER_ALPHABET.Length);
        foreach (char encoded in SUBSTITUTION_CIPHER_ALPHABET)
        {
            this.reverseSubstitutionCipherDictionary.Add(encoded, this.ReverseSubstituteChar(encoded));
        }
        this.reverseBase32Dictionary = new Dictionary<char, uint>(BASE32_ALPHABET.Length);
        foreach (char encoded in BASE32_ALPHABET)
        {
            this.reverseBase32Dictionary.Add(encoded, (uint)BASE32_ALPHABET.IndexOf(encoded));
        }
    }

    private char ReverseSubstituteChar(char c)
    {
        int index = SUBSTITUTION_CIPHER_ALPHABET.IndexOf(c) - 4;
        return SUBSTITUTION_CIPHER_ALPHABET[(index + SUBSTITUTION_CIPHER_ALPHABET.Length) % SUBSTITUTION_CIPHER_ALPHABET.Length];
    }

    public List<Dictionary<string, string>> ExtractEncodedDomains(IEnumerable<string> queriedDomains)
    {
        IDictionary<string, List<string>> guidDomainDictionary = new SortedDictionary<string, List<string>>();
        Dictionary<string, string> base32EncodedSegments = new Dictionary<string, string>();
        Dictionary<string, string> substitutionCipherSegments = new Dictionary<string, string>();
        List<Dictionary<string,string>> results = new List<Dictionary<string, string>>();

        foreach (string queriedDomain in queriedDomains.Where(s => s.Length > 16))
        {
            try
            {
                string subdomain = queriedDomain.Split('.').First().Trim();
                if (subdomain.Length > 16)
                {
                    string secureString = subdomain.Substring(0, 15);
                    byte[] guidBytes = new byte[8];
                    Array.Copy(this.DecryptSecureString(secureString), 0, guidBytes, 0, 8);
                    string guidString = BitConverter.ToString(guidBytes).Replace("-", string.Empty);
                    string encodedDomain = subdomain.Substring(16);
                    string decodedDomain;
                    if (encodedDomain.StartsWith("00"))
                    {
                        decodedDomain = UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(encodedDomain.Substring(2)).ToArray());
                        if (!base32EncodedSegments.ContainsKey(guidString))
                        {
                            base32EncodedSegments.Add(guidString, encodedDomain.Substring(2));
                            if (substitutionCipherSegments.ContainsKey(guidString))
                            {
                                string mergedDomain;
                                if (this.TryGetMergedBase32Domain(new[] { encodedDomain.Substring(2), substitutionCipherSegments[guidString] }, out mergedDomain))
                                {
                                    string previousDomain = mergedDomain.Substring(decodedDomain.Length);
                                    if (guidDomainDictionary.ContainsKey(guidString))
                                    {
                                        var l = guidDomainDictionary[guidString];
                                        l[l.Count - 1] = previousDomain;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        decodedDomain = this.DecodeDomainString(encodedDomain);
                        if (base32EncodedSegments.ContainsKey(guidString))
                        {
                            string mergedDomain;
                            string previousSegments = base32EncodedSegments[guidString];
                            if (previousSegments.Contains(encodedDomain))
                            {
                                decodedDomain = string.Empty;
                                if (previousSegments.EndsWith(encodedDomain))
                                {
                                    if (this.TryGetMergedBase32Domain(new[] { previousSegments }, out mergedDomain))
                                    {
                                        string firstDecodedDomainSegment = UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(previousSegments.Substring(0, previousSegments.Length - encodedDomain.Length)).ToArray());
                                        decodedDomain = mergedDomain.Substring(firstDecodedDomainSegment.Length);
                                    }
                                }
                            }
                            else if (this.TryGetMergedBase32Domain(new[] { previousSegments, encodedDomain }, out mergedDomain))
                            {
                                decodedDomain = mergedDomain.Substring(UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(previousSegments).ToArray()).Length);
                                base32EncodedSegments[guidString] = string.Join("", previousSegments, encodedDomain);
                            }
                        }
                        else if (!substitutionCipherSegments.ContainsKey(guidString))
                            substitutionCipherSegments.Add(guidString, encodedDomain);
                    }

                    //Console.WriteLine(string.Join("\t", guidString, decodedDomain, subdomain));
                    Dictionary<string, string> item = new Dictionary<string, string>();
                    item.Add("guidString", guidString);
                    item.Add("decodeDomain", decodedDomain);
                    item.Add("subdomain", subdomain);
                    results.Add(item);

                    List<string> domainSegments;
                    if (guidDomainDictionary.ContainsKey(guidString))
                    {
                        domainSegments = guidDomainDictionary[guidString];
                        if (string.IsNullOrEmpty(decodedDomain) || domainSegments.Contains(decodedDomain))
                            continue;
                    }
                    else
                    {
                        domainSegments = new List<string>() { string.Empty };//separator between last segment and other segments
                        guidDomainDictionary.Add(guidString, domainSegments);
                    }
                    if (this.IsLastDomainSegment(subdomain[15], subdomain[0]))
                        domainSegments.Add(decodedDomain);
                    else
                        domainSegments.Insert(0, decodedDomain);
                }
            }
            catch { }

        }

        /*foreach (var guidAndDomain in guidDomainDictionary)
        {
            if (guidAndDomain.Value.Last() != string.Empty)//only print domains that we have the last segment for
                Console.WriteLine(string.Join("\t", guidAndDomain.Key, string.Join("", guidAndDomain.Value)));
        }*/

        return results;
    }

    private bool TryGetMergedBase32Domain(IEnumerable<string> base32EncodedSegments, out string mergedDomain)
    {
        if (base32EncodedSegments.Where(s => s.StartsWith("0")).Any())
        {
            if (this.TryGetMergedBase32Domain(base32EncodedSegments.Select(s => s.TrimStart('0')), out mergedDomain))
                return true;
        }
        mergedDomain = UTF8Encoding.UTF8.GetString(this.Base32DecodeBinary(string.Join("", base32EncodedSegments)).ToArray());
        return mergedDomain.All((c) => this.reverseSubstitutionCipherDictionary.ContainsKey(char.ToLower(c)) || SPECIAL_CHARS.Contains(c));
    }

    //Inverted OrionImprovementBusinessLayer.CryptoHelper.CreateString(int n, char c)
    private bool IsLastDomainSegment(char c, char firstChar)
    {
        if (c == (35 + firstChar) % 36 + 48)
            return true;
        else if (c == (35 + firstChar) % 36 + 87)
            return true;
        else
            return false;
    }

    //Inverted OrionImprovementBusinessLayer.CryptoHelper.Base64Decode(string s)
    private string DecodeDomainString(string encodedDomain)
    {
        StringBuilder decodedDomain = new StringBuilder();
        bool nextCharIsSpecial = false;
        foreach (char c in encodedDomain)
        {
            if (nextCharIsSpecial)
            {
                int index = SUBSTITUTION_CIPHER_ALPHABET.IndexOf(c);
                decodedDomain.Append(SPECIAL_CHARS[(index + SPECIAL_CHARS.Length) % SPECIAL_CHARS.Length]);
                nextCharIsSpecial = false;
            }
            else if (SPECIAL_CHARS.Contains(c))
            {
                nextCharIsSpecial = true;
            }
            else if (this.reverseSubstitutionCipherDictionary.ContainsKey(c))
                decodedDomain.Append(this.reverseSubstitutionCipherDictionary[c]);
            else
            {//backup for unexpected input
                decodedDomain.Append(this.ReverseSubstituteChar(c));
            }
        }
        return decodedDomain.ToString();
    }

    //Inverted OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString(byte[] data, bool flag)
    private byte[] DecryptSecureString(string secureString)
    {
        byte[] decodedBytes = this.Base32DecodeBinary(secureString).ToArray();
        byte[] decryptedBytes = new byte[decodedBytes.Length - 1];
        byte xorKey = decodedBytes[0];
        for (int i = 0; i < decryptedBytes.Length; i++)
            decryptedBytes[i] = (byte)(decodedBytes[i + 1] ^ xorKey);
        return decryptedBytes;
    }

    //Inverted OrionImprovementBusinessLayer.CryptoHelper.Base64Encode(byte[] bytes, bool rt)
    private IEnumerable<byte> Base32DecodeBinary(string encodedBinary)
    {
        if (!encodedBinary.All((char c) => this.reverseBase32Dictionary.Keys.Contains(c)))
        {
            encodedBinary = string.Concat(encodedBinary.Where((char c) => this.reverseBase32Dictionary.Keys.Contains(c)));
        }
        uint buffer = 0u;
        int bitCount = 0;
        foreach (char c in encodedBinary)
        {
            buffer |= (this.reverseBase32Dictionary[c] << bitCount);
            bitCount += 5;
            if (bitCount > 7)
            {
                yield return (byte)buffer;
                buffer >>= 8;
                bitCount -= 8;
            }
        }
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'SunburstDomainDecoder').Type)
{
    Add-Type -TypeDefinition $SunburstDefinition
}
$Sunburst = New-Object SunburstDomainDecoder


$DnsList = New-Object System.Collections.Generic.List[string]
if ($DnsQuery -ne "") {
    $DnsList.Add($DnsQuery)
}
else {
    Get-Content $DnsQueryfile | ForEach-Object {
        $DnsList.Add($_)
    }
}

$decodedDomains = $Sunburst.ExtractEncodedDomains($DnsList.ToArray())

$output = $decodedDomains | Group-Object -property {$_["guidString"]} | ForEach-Object {
    if ($_.Count -gt 1)
    {    
        [PSCustomObject]@{
            HostId = $_.Name
            DecodedDomains = $_.Group.decodeDomain -Join '|'
            DnsRequests = $_.Group.subdomain -Join '|'
        }
    }
    else {
        [PSCustomObject]@{
            HostId = $_.Name
            DecodedDomains = $_.Group.decodeDomain
            DnsRequests = $_.Group.subdomain
        }
    }
}
if ($OutFileCsv)
{
    $output | Export-Csv -NoTypeInformation -Path $OutFileCsv
}
if (!$NoOutputOnScreen){
    $output | Format-Table
}

if ($MatchSystemGuid)
{
    if ($Mac -eq "")
    {
        Write-Host "[*] Mac Address not provided. Using MAC addresses from current machine:"
        $MacAddresses = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ? {$_.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback} | % { $_.GetPhysicalAddress().ToString() }
        $MacAddresses
    }
    else
    {
        $MacAddresses = @($Mac)
    }

    if ($Domain -eq "")
    {
        Write-Host "[*] Domain name not provided. Using domain from current machine:"
        $Domain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
        $Domain
    }

    if ($MachineGuid -eq "")
    {
        Write-Host "[*] Machine Guid not provided. Using Machine Guid from current machine:"
        $MachineGuid = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography -Name MachineGuid | select -ExpandProperty MachineGuid
        $MachineGuid
    }

    foreach ($MacAddress in $MacAddresses) {
        $currentHostId = GetHostIdFromParams -Mac $MacAddress -Domain $Domain -Guid $MachineGuid
        Write-Host -ForegroundColor Green "[*] Checking matches for Mac Address: $MacAddress Domain: $Domain MachineGuid: $MachineGuid -> Computed System Id: $currentHostId"
        
        if ($currentHostId -in ($output.HostId))
        {
            $output | Where-Object {$_.HostId -eq $currentHostId} | ForEach-Object {                    
                Write-Host -ForegroundColor Yellow "[!] MATCH - The query with subdomain $($_.DnsRequests) was made from system with Mac Address: $MacAddress Domain: $Domain MachineGuid: $MachineGuid"
            }
        }
        else {
            Write-Host "[-] HostId currentHostId does not match any decoded value."
        }
    }
}
