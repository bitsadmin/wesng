# Windows Exploit Suggester - Next Generation (WES-NG)
WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 11, including their Windows Server counterparts, is supported.

At the BITSADMIN blog an in-depth article on WES-NG is available: [Windows Security Updates for Hackers](https://blog.bitsadmin.com/windows-security-updates-for-hackers).

## Usage
1. Download WES-NG using `pip install wesng` or using the following commandline: `git clone https://github.com/bitsadmin/wesng --depth 1`
2. Obtain the latest database of vulnerabilities by executing the command `wes.py --update`
3. There are two options to check for missing patches:
    a. Launch `missingkbs.vbs` or `missingkbs.ps1` on the host to have Windows determine which patches are missing
    b. Use Windows' built-in `systeminfo.exe` tool to obtain the system information of the local system, or from a remote system using `systeminfo /S MyRemoteHost`, and redirect this to a file: `systeminfo > systeminfo.txt`
4. Depending on the method chosen in step 3 execute WES-NG:
    a. With the `missing.txt` file as input: `wes.py --missing missing.txt` (or `wes.py -m missing.txt`)
    b. With the `systeminfo.txt` file as the parameter: `wes.py systeminfo.txt`
WES-NG then uses the database to determine which patches are applicable to the system and to which vulnerabilities are currently exposed, including exploits if available.
5. As the data provided by Microsoft's MSRC feed is frequently incomplete and false positives are reported by `wes.py`, @DominicBreuker contributed the `--muc-lookup` parameter to validate identified missing patches from the `systeminfo.txt` file against Microsoft's Update Catalog. Additionally, make sure to check the [Eliminating false positives](https://github.com/bitsadmin/wesng/wiki/Eliminating-false-positives) page at the Wiki on how to interpret the results.
For an overview of all available parameters for `missingkbs.vbs`, `missingkbs.ps1` and `wes.py`, check [CMDLINE.md](https://github.com/bitsadmin/wesng/blob/master/CMDLINE.md).

## Demo
![Gif animation showing usage of Windows Exploit Suggester - Next Generation](https://raw.githubusercontent.com/bitsadmin/wesng/master/demo.gif)

## Collector
This GitHub repository regularly updates the database of vulnerabilities, so running `wes.py` with the `--update` parameter gets the latest version.
If manual generation of the .csv file with hotfix information is required, use the scripts from the [/collector](collector) folder to compile the database. Read the comments at the top of each script and execute them in the order as they are listed below. Executing these scripts will produce definitions.zip.
The WES-NG collector pulls information from various sources:
- Microsoft Security Bulletin Data: KBs for older systems [1]
- MSRC: The Microsoft Security Update API of the Microsoft Security Response Center (MSRC): Standard source of information for modern Microsoft Updates [2]
- NIST National Vulnerability Database (NVD): Complement vulnerabilities with Exploit-DB links [3]
These are combined into a single .csv file which is compressed and hosted in this GitHub repository.

## Rationale
I developed WES-NG because while [GDSSecurity's Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester/) worked excellently for operating systems in the Windows XP and Windows Vista era, GDSSecurity's Windows-Exploit-Suggester does not work for operating systems like Windows 11 and vulnerabilities published in recent years. This is because Microsoft replaced the Microsoft Security Bulletin Data Excel file [1] on which GDSSecurity's Windows-Exploit-Suggester is fully dependent, by the MSRC API [2]. The Microsoft Security Bulletin Data Excel file has not been updated since Q1 2017, so later operating systems and vulnerabilities cannot be detected. Thanks [@gdssecurity](https://twitter.com/gdssecurity), for this great tool which has served many of us for so many years!

## Bugs
- Bugs can be submitted via the [Issues](https://github.com/bitsadmin/wesng/issues) page
- For false positives in results, please read the [Eliminating false positives](https://github.com/bitsadmin/wesng/wiki/Eliminating-false-positives) page at the Wiki first. In case that doesn't significantly reduce the number of false positives, follow the steps at the [Report false positives](https://github.com/bitsadmin/wesng/wiki/Reporting-false-positives) page on the [Wiki](https://github.com/bitsadmin/wesng/wiki).

## Changelog
See [CHANGELOG.md](https://github.com/bitsadmin/wesng/blob/master/CHANGELOG.md)

## Improvements
- Add support for [NoPowerShell](https://github.com/bitsadmin/nopowershell/)'s `Get-SystemInfo` cmdlet output
- Add support for alternative output formats of `systeminfo` (csv, table)
- More testing on the returned false positive vulnerabilities - see also the [wiki](https://github.com/bitsadmin/wesng/wiki)

## References
[1] https://www.microsoft.com/download/details.aspx?id=36982

[2] https://portal.msrc.microsoft.com/en-us/developer

[3] https://nvd.nist.gov/vuln/data-feeds

#
**Authored by Arris Huijgen ([@bitsadmin](https://twitter.com/bitsadmin/) - https://github.com/bitsadmin/)**
