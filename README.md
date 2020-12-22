# Description
This script can be used to:
- Decode DNS queries based on the DGA algorithm used in the SUNBURST backdoor
- Identify if provided DNS queries were generated from a certain machine

The SUNBURST backdoor uses the following three parameters to create a "Host Id" used in the DNS requests:

- MAC address of the network interface
- Internal domain name that the machine is joined to
- Machine Guid from `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`

You can provide these values to the script together with DNS queries to match. If not provided, the DNS queries will be matched against the current machine where the script is running.

For more info, see our [blog post](https://blog.truesec.com/2020/12/17/the-solarwinds-orion-sunburst-supply-chain-attack/).

# Usage
```
# Decode single query
.\Invoke-SunburstDecoder.ps1 -DnsQuery "eo5talvjhsjtgtcs3iquvhthi0c12eu1.appsync-api.us-east-2.avsvmcloud.com"

# Decode list of queries
.\Invoke-SunburstDecoder -DnsQueryFile .\uniq-hostnames.txt

# Decode list of queries and output to file
.\Invoke-SunburstDecoder -DnsQueryFile .\uniq-hostnames.txt -OutFileCsv .\result.csv -NoOutputOnScreen

# Check if a DNS query was generated from the current machine
.\Invoke-SunburstDecoder.ps1 -DnsQuery "eo5talvjhsjtgtcs3iquvhthi0c12eu1.appsync-api.us-east-2.avsvmcloud.com" -MatchSystemGuid

# Check if any entry in a list of DNS queries matches a certain machine (based on MAC address, Machine Guid, and internal domain name)
.\Invoke-SunburstDecoder -DnsQueryFile .\uniq-hostnames.txt -MatchSystemGuid -Mac "B4B686FA33A2" -Domain "internal.ad.local" -MachineGuid "3da89297-0056-41fc-9ad6-e9d1479a8cdc"
```

# Credits
We based our script on the [great work](https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS) done by Erik Hjelmvik, Netresec