The following commandline options are available for WES-NG v0.94.

```
usage: wes.py [-u] [--update-wes] [-p INSTALLEDPATCH [INSTALLEDPATCH ...]]
              [-e] [--hide HIDDENVULN [HIDDENVULN ...]] [-o [OUTPUTFILE]] [-h]
              systeminfo [definitions]

Windows Exploit Suggester 0.94 ( https://github.com/bitsadmin/wesng/ )

positional arguments:
  systeminfo            Specify systeminfo.txt file
  definitions           List of known vulnerabilities (default:
                        definitions.zip)

optional arguments:
  -u, --update          Download latest list of CVEs
  --update-wes          Download latest version of wes.py
  -p INSTALLEDPATCH [INSTALLEDPATCH ...], --patches INSTALLEDPATCH [INSTALLEDPATCH ...]
                        Manually specify installed patches in addition to the
                        ones listed in the systeminfo.txt file
  -e, --exploits-only   Show only vulnerabilities with known exploits
  --hide HIDDENVULN [HIDDENVULN ...]
                        Hide vulnerabilities of for example Adobe Flash Player
                        and Microsoft Edge
  -o [OUTPUTFILE], --output [OUTPUTFILE]
                        Store results in a file
  -h, --help            Show this help message and exit

examples:
  Download latest definitions
  wes.py --update
  wes.py -u

  Determine vulnerabilities
  wes.py systeminfo.txt
  
  Determine vulnerabilities and output to file
  wes.py systeminfo.txt --output vulns.csv
  wes.py systeminfo.txt -o vulns.csv
  
  Determine vulnerabilities explicitly specifying KBs to reduce false-positives
  wes.py systeminfo.txt --patches KB4345421 KB4487017
  wes.py systeminfo.txt -p KB4345421 KB4487017

  Determine vulnerabilities explicitly specifying definitions file
  wes.py systeminfo.txt C:\tmp\mydefs.zip

  List only vulnerabilities with exploits, excluding Edge and Flash
  wes.py systeminfo.txt --exploits-only --hide "Internet Explorer" Edge Flash
  wes.py systeminfo.txt -e --hide "Internet Explorer" Edge Flash
  
  Download latest version of WES-NG
  wes.py --update-wes
```
