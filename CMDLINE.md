The following commandline options are available for WES-NG v1.0.

# wes.py
```
usage: wes.py [-u] [--definitions [DEFINITIONS]]
              [-p INSTALLEDPATCH [INSTALLEDPATCH ...]] [-d] [-e]
              [--hide HIDDENVULN [HIDDENVULN ...]] [-i IMPACTS [IMPACTS ...]]
              [-s SEVERITIES [SEVERITIES ...]] [-o [OUTPUTFILE]]
              [--muc-lookup] [--os [OPERATING_SYSTEM]] [-c] [-h]
              [--update-wes]

Windows Exploit Suggester 1.00 ( https://github.com/bitsadmin/wesng/ )

optional arguments:
  -u, --update          Download latest list of CVEs
  --definitions [DEFINITIONS]
                        Definitions zip file (default: definitions.zip)
  -p INSTALLEDPATCH [INSTALLEDPATCH ...], --patches INSTALLEDPATCH [INSTALLEDPATCH ...]
                        Manually specify installed patches in addition to the
                        ones listed in the systeminfo.txt file
  -d, --usekbdate       Filter out vulnerabilities of KBs published before the
                        publishing date of the most recent KB installed
  -e, --exploits-only   Show only vulnerabilities with known exploits
  --hide HIDDENVULN [HIDDENVULN ...]
                        Hide vulnerabilities of for example Adobe Flash Player
                        and Microsoft Edge
  -i IMPACTS [IMPACTS ...], --impact IMPACTS [IMPACTS ...]
                        Only display vulnerabilities with a given impact
  -s SEVERITIES [SEVERITIES ...], --severity SEVERITIES [SEVERITIES ...]
                        Only display vulnerabilities with a given severity
  -o [OUTPUTFILE], --output [OUTPUTFILE]
                        Store results in a file
  --muc-lookup          Hide vulnerabilities if installed hotfixes are listed
                        in the Microsoft Update Catalog as superseding
                        hotfixes for the original BulletinKB
  --os [OPERATING_SYSTEM]
                        Specify operating system or ID from list when running
                        without this parameter
  -c, --color           Show console output in color (requires termcolor
                        library)
  -h, --help            Show this help message and exit
  --update-wes          Download latest version of wes.py

Examples:
  Download latest definitions
  wes.py --update
  wes.py -u

  Determine vulnerabilities
  wes.py systeminfo.txt
  
  Determine vulnerabilities using the qfe file. List the OS by first running the command without the --os parameter
  wes.py --qfe qfe.txt --os 'Windows 10 Version 20H2 for x64-based Systems'
  wes.py -q qfe.txt --os 9

  Determine vulnerabilities and output to file
  wes.py systeminfo.txt --output vulns.csv
  wes.py systeminfo.txt -o vulns.csv

  Determine vulnerabilities explicitly specifying KBs to reduce false-positives
  wes.py systeminfo.txt --patches KB4345421 KB4487017
  wes.py systeminfo.txt -p KB4345421 KB4487017
  
  Determine vulnerabilies filtering out out vulnerabilities of KBs that have been published before the publishing date of the most recent KB installed
  wes.py systeminfo.txt --usekbdate
  wes.py systeminfo.txt -d

  Determine vulnerabilities explicitly specifying definitions file
  wes.py systeminfo.txt --definitions C:\tmp\mydefs.zip

  List only vulnerabilities with exploits, excluding IE, Edge and Flash
  wes.py systeminfo.txt --exploits-only --hide "Internet Explorer" Edge Flash
  wes.py systeminfo.txt -e --hide "Internet Explorer" Edge Flash

  Only show vulnerabilities of a certain impact
  wes.py systeminfo.txt --impact "Remote Code Execution"
  wes.py systeminfo.txt -i "Remote Code Execution"
  
  Only show vulnerabilities of a certain severity
  wes.py systeminfo.txt --severity critical
  wes.py systeminfo.txt -s critical
  
  Show vulnerabilities based on missing patches 
  wes.py --missing missing.txt
  wes.py -m missing.txt
  
  Show vulnerabilities based on missing patches specifying OS
  wes.py --missing missing.txt --os "Windows 10 Version 1809 for x64-based Systems"
  wes.py -m missing.txt --os 2

  Validate supersedence against Microsoft's online Update Catalog
  wes.py systeminfo.txt --muc-lookup

  Show colored output 
  wes.py systeminfo.txt --color
  wes.py systeminfo.txt -c

  Download latest version of WES-NG
  wes.py --update-wes
```

# missingkbs.vbs
```
Windows Exploit Suggester: Missing KBs Identifier v1.0
https://github.com/bitsadmin/wesng/

Usage: missingkbs.vbs [/F] [/I:[filename]] [/P] [/O:[filename]]

Description:
    Compiles a list of missing KBs on the current system.
    These missing KBs are determined based either the online
    Microsoft Update service or WSUS if configured, or on an offline
    scanfile (wsusscn2.cab). This scanfile is either provided in the
    commandline or downloaded from the Microsoft Update site.
    By default the online Microsoft Update service is used (or WSUS if configured).

Parameter List:
    /F or /Offline  Perform an offline scan using a scanfile.
    /I:[filename]   Specify path to the scanfile (wsusscn2.cab). Implies /F and /P.
    /P              Preserve the scanfile.
    /O:[filename]   Specify filename to store the results in. By default the
                    file missing.txt in the current directory will be used.
    /D:[directory]  Just download the scanfile (don't check for missing KBs).
                    By default the file will be downloaded to the current directory.
    /? or /Help     Displays this help message.

Examples:
    Determine missing KBs using online Microsoft Update service (or WSUS if configured)
    cscript.exe missingkbs.vbs

    Determine missing KBs downloading the wsusscn2.cab scanfile and preserving it
    cscript.exe missingkbs.vbs /F /P

    Determine missing KBs using the offline wsusscn2.cab scanfile
    cscript.exe missingkbs.vbs /F /I:E:\tmp\wsusscn2.cab

    Determine missing KBs downloading the wsusscn2.cab scanfile saving results in out.txt
    cscript.exe missingkbs.vbs /F /O:E:\tmp\out.txt

    Download the scanfile to E:\tmp\
    cscript.exe missingkbs.vbs /D:E:\tmp
```

