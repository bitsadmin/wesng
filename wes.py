#!/usr/bin/python3
#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Windows Exploit Suggester - Next Generation
#
# Author: Arris Huijgen (@bitsadmin)
# Website: https://github.com/bitsadmin
import sys, csv, re, argparse, os, urllib.request, zipfile

VERSION = 0.93
WEB_URL = 'https://github.com/bitsadmin/wesng/'
FILENAME = 'wes.py'

filtered = None

# Mapping table between build numbers and versions to be able to import systeminfo output files
buildnumbers = {
    # Windows XP / Server 2003 [R2]
    # ..

    # Windows Vista / Server 2008
    # ..

    # Windows 7 / Server 2008 R2
    7601: 'Service Pack 1',

    # Windows 8 / Server 2012
    # ..

    # Windows 8.1 / Server 2012 R2
    # ..

    # Windows 10 / Server
    10240: 1507,
    10586: 1511,
    14393: 1607,
    15063: 1703,
    16299: 1709,
    17134: 1803,
    17763: 1809
}

def main():
    args = parse_arguments()

    # Update
    if args.perform_update:
        print('[+] Updating list of vulnerabilities')
        urllib.request.urlretrieve('https://raw.githubusercontent.com/bitsadmin/wesng/master/CVEs.zip', 'CVEs.zip')
        with zipfile.ZipFile("CVEs.zip", "r") as cveszip:
            cveszip.extract("CVEs.csv")
        os.remove('CVEs.zip')
        return

    # Obtain arguments
    systeminfo_txt = args.systeminfo
    cves_csv = args.cves

    # Parse encoding of systeminfo.txt input
    print('[+] Parsing systeminfo output')
    systeminfo = open(systeminfo_txt, 'rb').read()
    try:
        import chardet
        encoding = chardet.detect(systeminfo)
        systeminfo = systeminfo.decode(encoding['encoding'])
    except ImportError:
        print('[!] Warning: chardet module not installed. In case of encoding errors, install chardet using: pip3 install chardet')
        systeminfo = systeminfo.decode('ascii')

    # OS Version
    regex_version = re.compile(r'.*?:\s+((\d+\.?)+) ((Service Pack (\d)|N/A|.+) )?\w+ (\d+).*', re.MULTILINE | re.IGNORECASE)
    systeminfo_matches = regex_version.findall(systeminfo)
    if len(systeminfo_matches) == 0:
        print('[-] Not able to detect OS version based on provided input file')
        exit(1)
    systeminfo_matches = systeminfo_matches[0]
    mybuild = int(systeminfo_matches[5])
    servicepack = systeminfo_matches[4]

    # OS Name
    win = re.findall('.*?Microsoft[\(R\)]{0,3} Windows[\(R\)]{0,3} (Serverr? )?(\d+\.?\d?( R2)?|XP|VistaT).*', systeminfo, re.MULTILINE | re.IGNORECASE)[0][1]

    # System Type
    arch = re.findall('.*?([\w\d]+?)-based PC.*', systeminfo, re.MULTILINE | re.IGNORECASE)[0]

    # Hotfix(s)
    hotfix_matches = re.findall('.*KB\d+.*', systeminfo, re.MULTILINE | re.IGNORECASE)
    hotfixes = []
    for match in hotfix_matches:
        hotfixes.append(re.search('.*KB(\d+).*', match, re.MULTILINE | re.IGNORECASE).group(1))

    # Determine Windows 10 version based on build
    version = None
    for build in buildnumbers:
        if mybuild == build:
            version = buildnumbers[build]
            break
        if mybuild > build:
            version = buildnumbers[build]
        else:
            break

    # Compile name for product filter
    # Architecture
    if win not in ['XP', 'VistaT', '2003', '2003 R2']:
        if arch == 'X86':
            arch = '32-bit'
        elif arch == 'x64':
            arch = 'x64-based'

    # Client OSs
    if win == 'XP':
        productfilter = 'Microsoft Windows XP'
        if arch != 'X86':
            productfilter += ' Professional %s Edition' % arch
        if servicepack:
            productfilter += ' Service Pack %s' % servicepack
    elif win == 'VistaT':
        productfilter = 'Windows Vista'
        if arch != 'x86':
            productfilter += ' %s Edition' % arch
        if servicepack:
            productfilter += ' Service Pack %s' % servicepack
    elif win == '7':
        pversion = '' if version is None else ' ' + version
        productfilter = 'Windows %s for %s Systems%s' % (win, arch, pversion)
    elif win == '8':
        productfilter = 'Windows %s for %s Systems' % (win, arch)
    elif win == '8.1':
        productfilter = 'Windows %s for %s Systems' % (win, arch)
    elif win == '10':
        productfilter = 'Windows %s Version %s for %s Systems' % (win, version, arch)

    # Server OSs
    elif win == '2003':
        if arch == 'X86':
            arch = ''
        elif arch == 'x64':
            arch = ' x64 Edition'
        pversion = '' if version is None else ' ' + version
        productfilter = 'Microsoft Windows Server %s%s%s' % (win, arch, pversion)
    # elif win == '2003 R2':
    # Not possible to distinguish between Windows Server 2003 and Windows Server 2003 R2 based on the systeminfo output
    # See: https://serverfault.com/questions/634149/will-systeminfos-os-name-line-distinguish-between-windows-2003-and-2003-r2
    # In CVEs.csv there is a distinction though between 2003 and 2003 R2. We will need to add support for explicitly
    # providing the OS in the wes.py commandline.
    elif win == '2008':
        pversion = '' if version is None else ' ' + version
        productfilter = 'Windows Server %s for %s Systems%s' % (win, arch, pversion)
    elif win == '2008 R2':
        pversion = '' if version is None else ' ' + version
        productfilter = 'Windows Server %s for %s Systems%s' % (win, arch, pversion)
    elif win == '2012':
        productfilter = 'Windows Server %s' % win
    elif win == '2012 R2':
        productfilter = 'Windows Server %s' % win
    elif win == '2016':
        productfilter = 'Windows Server %s' % win
    elif win == '2019':
        productfilter = 'Windows Server %s' % win
    else:
        print("[-] Failed assessing Windows version %s" % win)
        exit(1)

    print("""[+] Operating System
    - Name: %s
    - Generation: %s
    - Build: %s
    - Version: %s
    - Architecture: %s
    - Installed hotfixes: %s""" % (productfilter, win, mybuild, version, arch, ', '.join(['KB%s' % kb for kb in hotfixes])))

    print('[+] Loading CSV with CVEs')
    # DatePosted,CVE,BulletinKB,Title,AffectedProduct,AffectedComponent,Severity,Impact,Supersedes,Exploits
    f = open(cves_csv, 'r')
    cves = csv.DictReader(f, delimiter=',', quotechar='"')

    print('[+] Determining missing patches')
    # Filter CVEs that are applicable to this system
    global filtered
    filtered = filter(lambda cve: productfilter in cve['AffectedProduct'], cves)
    filtered = list(filtered)
    for entry in filtered:
        entry['Relevant'] = True

    # Collect patches that are already superseeded and
    # merge these with the patches found installed on the system
    hotfixes += [cve['Supersedes'] for cve in filtered]
    hotfixes = list(filter(None, set(hotfixes)))

    for hotfix in hotfixes:
        mark_superseeded_hotfix(hotfix)

    # Check if left over KBs contain overlaps, for example a separate security hotfix
    # which is also contained in a monthly rollup update
    check = filter(lambda cve: cve['Relevant'], filtered)
    supersedes = set([x['Supersedes'] for x in check])
    checked = filter(lambda cve: cve['BulletinKB'] in supersedes, check)
    for c in checked:
        c['Relevant'] = False

    # Final results
    found = list(filter(lambda cve: cve['Relevant'], filtered))
    for f in found:
        del f['Relevant']

    # Apply display filters
    hiddenvulns = list(map(lambda s: s.lower(), args.hiddenvulns))
    filtered = []
    for cve in found:
        add = True
        for hidden in hiddenvulns:
            if hidden in cve['AffectedComponent'].lower() or hidden in cve['AffectedProduct'].lower():
                add = False
                break
        if add:
            filtered.append(cve)

    if args.only_exploits:
        filtered = list(filter(lambda res: res['Exploits'], filtered))

    # Display results
    if len([filtered]) > 0:
        print('[+] Found vulnerabilities\n')
        printresults(filtered)
    else:
        print('[-] No vulnerabilities found\n')

    print('[+] Done. Displaying %d of the %d vulnerabilities found.' % (len(filtered), len(found)))


def mark_superseeded_hotfix(superseeded):
    global filtered

    # Locate all CVEs for KB
    foundSuperseeded = filter(lambda cve: cve['Relevant'] and cve['BulletinKB'] == superseeded, filtered)
    for ss in foundSuperseeded:
        ss['Relevant'] = False

        # In case there is a child, recurse (depth first)
        if ss['Supersedes']:
            mark_superseeded_hotfix(ss['Supersedes'])


def printresults(results):
    for res in results:
        exploits = res['Exploits']
        label = 'Exploit'
        value = 'n/a'
        if len(exploits) > 0:
            value = exploits
        if ',' in exploits:
            label = 'Exploits'

        print("""Date: %s
CVE: %s
KB: KB%s
Affected product: %s
Affected component: %s
Severity: %s
Impact: %s
%s: %s
""" % (res['DatePosted'], res['CVE'], res['BulletinKB'], res['AffectedProduct'], res['AffectedComponent'], res['Severity'], res['Impact'], label, value))


def check_file_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('File \'%s\' does not exist.' % value)

    return value

def check_cves_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('CVEs file \'%s\' does not exist. Try running %s --update first.' % (value, FILENAME))

    return value


def parse_arguments():
    examples = r'''examples:
  Download latest list of CVEs
  {0} --update
  {0} -u

  Determine vulnerabilities
  {0} systeminfo.txt

  Determine vulnerabilities explicitly specifying CVEs csv
  {0} systeminfo.txt C:\tmp\CVEs.csv

  List only vulnerabilities with exploits, excluding Edge and Flash
  {0} systeminfo.txt --exploits-only --hide "Internet Explorer" Edge Flash
  {0} systeminfo.txt -e --hide "Internet Explorer" Edge Flash
'''.format(FILENAME)

    parser = argparse.ArgumentParser(
        description='Windows Exploit Suggester %.2f ( %s )' % (VERSION, WEB_URL),
        add_help=False,
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Update
    parser.add_argument('-u', '--update', dest='perform_update', action='store_true', help='Download latest list of CVEs')
    args, xx = parser.parse_known_args()
    if args.perform_update:
        return args

    # Options
    parser.add_argument('systeminfo', action='store', type=check_file_exists, help='Specify systeminfo.txt file')
    parser.add_argument('cves', action='store', nargs='?', type=check_cves_exists, default='CVEs.csv', help='List of known vulnerabilities (default: CVEs.csv)')
    parser.add_argument('-e', '--exploits-only', dest='only_exploits', action='store_true', help='Show only vulnerabilities with known exploits')
    parser.add_argument('--hide', dest='hiddenvulns', nargs='+', default='', help='Hide vulnerabilities of for example Adobe Flash Player and Microsoft Edge')
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')

    # Always show full help when no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    return parser.parse_args()


if __name__ == '__main__':
    main()
