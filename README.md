# Windows Exploit Suggester - Next Generation (WES-NG)
WES-NG is a tool which based on the output of Windows' `systeminfo` utility provides you with the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported.

## Usage
1. Obtain the latest database of vulnerabilities by executing the `wes.py --update` commandline.
2. Next, use Windows' built-in `systeminfo.exe` tool obtain the system information of the local system or from a remote system using `systeminfo.exe /S MyRemoteHost`, and redirect this to a file: `systeminfo > systeminfo.txt`
3. Execute WES-NG with the systeminfo.txt output file as parameter: `wes.py systeminfo.txt`. WES-NG then uses the database to determine which patches are applicable to the system and to which vulnerabilities it is currently exposed, including exploits if available.

## Screenshot
[Gif animation showing usage of Windows Exploit Suggester - Next Generation](https://raw.githubusercontent.com/bitsadmin/wesng/master/demo.gif)

## Collector
This GitHub repository will regularly update the database of vulnerabilities so running `wes.py` with the `--update` parameter will get you the latest version.
In case for some reason you want to generate the .csv file with hotfix information yourself, use the scripts from the [/collector](collector) folder to compile the database. Read the comments at the top of each script and execute them in the order as they are listed below. After executing these scripts you will end up with the CVEs.csv file.
The WES-NG collector pulls information from various sources:
- Microsoft Security Bulletin Data: KBs for older systems [1]
- MSRC: The Microsoft Security Update API of the Microsoft Security Response Center (MSRC) is nowadays the standardized way to obtain information about Microsoft updates [2]
- NIST National Vulnerability Database (NVD): Complement vulnerabilities with Exploit-DB links [3]
These are combined into a single .csv file which is compressed and hosted in this GitHub repository.

## Rationale
I developed WES-NG because [GDSSecurity's Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester/) tool which used to work excellent for operating systems in the Windows XP and Windows Vista era, does not work for more recent operating systems like Windows 10 and vulnerabilities published in recent years. This is because Microsoft replaced the Microsoft Security Bulletin Data Excel file [1], on which GDSSecurity's Windows-Exploit-Suggester is fully dependent, by the MSRC API [2]. The Microsoft Security Bulletin Data Excel file has not been updated since Q1 2017, so later operating systems and vulnerabilities cannot be detected. Thanks [GDSSecurity](https://github.com/GDSSecurity/), for this great tool which has served many of us for so many years!

## Improvements
- Add support for [NoPowerShell's](https://github.com/bitsadmin/nopowershell/) `Get-SystemInfo` cmdlet output
- Add support for `wmic qfe` output together with support for parameters to manually specify the operating system
- Add support for alternative output formats of `systeminfo` (csv, table)
- More testing on the false positive vulnerabilities that are returned


[1] https://www.microsoft.com/download/details.aspx?id=36982
[2] https://portal.msrc.microsoft.com/en-us/developer
[3] https://nvd.nist.gov/vuln/data-feeds


**Authored by Arris Huijgen ([@bitsadmin](https://twitter.com/bitsadmin/) - https://github.com/bitsadmin/)**