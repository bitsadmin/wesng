#!/usr/bin/python3
#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Windows Exploit Suggester - Next Generation
#
# Author: Arris Huijgen (@bitsadmin)
# Website: https://github.com/bitsadmin

from __future__ import print_function

import sys, csv, re, argparse, os, zipfile, io
import logging
from collections import Counter, OrderedDict

if sys.version_info.major == 2:
    from urllib import urlretrieve
    ModuleNotFoundError = ImportError
else:
    from urllib.request import urlretrieve

try:
    import chardet

    def charset_convert(data):
        encoding = chardet.detect(data)
        data = data.decode(encoding['encoding'], 'ignore')

        if sys.version_info.major == 2:
            data = data.encode(sys.getfilesystemencoding())

        return data

except (ImportError, ModuleNotFoundError):
    def charset_convert(data):
        data = data.decode('ascii', 'ignore')

        if sys.version_info.major == 2:
            data = data.encode(sys.getfilesystemencoding())

        return data

    logging.warning(
        'chardet module not installed. In case of encoding '
        'errors, install chardet using: pip{} install chardet'.format(
            sys.version_info.major))


class WesException(Exception):
    pass


VERSION = 0.94
WEB_URL = 'https://github.com/bitsadmin/wesng/'
BANNER = 'Windows Exploit Suggester %.2f ( %s )' % (VERSION, WEB_URL)
FILENAME = 'wes.py'

# Mapping table between build numbers and versions to be able to import systeminfo output files
buildnumbers = OrderedDict([
    # Windows XP / Server 2003 [R2]
    # ..

    # Windows Vista / Server 2008
    # ..

    # Windows 7 / Server 2008 R2
    (7601, 'Service Pack 1'),

    # Windows 8 / Server 2012
    # ..

    # Windows 8.1 / Server 2012 R2
    # ..

    # Windows 10 / Server
    (10240, 1507),
    (10586, 1511),
    (14393, 1607),
    (15063, 1703),
    (16299, 1709),
    (17134, 1803),
    (17763, 1809)
])


def main():
    args = parse_arguments()

    # Update definitions
    if args.perform_update:
        print('[+] Updating definitions')
        urlretrieve('https://raw.githubusercontent.com/bitsadmin/wesng/master/definitions.zip', 'definitions.zip')
        cves, date = load_defintions('definitions.zip')
        print('[+] Obtained definitions created at %s' % date)
        return

    # Update application
    if args.perform_wesupdate:
        print('[+] Updating wes.py')
        urlretrieve('https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py', 'wes.py')
        print('[+] Updated to the latest version. Relaunch wes.py to use.')
        return

    # Banner
    print(BANNER)

    # Parse encoding of systeminfo.txt input
    print('[+] Parsing systeminfo output')
    systeminfo_data = open(args.systeminfo, 'rb').read()
    productfilter, win, mybuild, version, arch, hotfixes = determine_product(systeminfo_data)
    manual_hotfixes = list(set([patch.upper().replace('KB', '') for patch in args.installedpatch]))

    print("""[+] Operating System
    - Name: %s
    - Generation: %s
    - Build: %s
    - Version: %s
    - Architecture: %s
    - Installed hotfixes: %s
    - Manually specified hotfixes: %s""" % (productfilter, win, mybuild, version, arch,
                                            ', '.join(['KB%s' % kb for kb in hotfixes]),
                                            ', '.join(['KB%s' % kb for kb in manual_hotfixes])))

    # Append manually specified KBs to list of hotfixes
    hotfixes = list(set(hotfixes + manual_hotfixes))

    print('[+] Loading definitions')
    try:
        cves, date = load_defintions(args.definitions)

        print('    - Creation date of definitions: %s' % date)

        print('[+] Determining missing patches')
        filtered, found = determine_missing_patches(productfilter, cves, hotfixes)

    except WesException as e:
        print('[-] ' + str(e))
        exit(1)

    print('[+] Applying display filters')
    filtered = apply_display_filters(filtered, found, args.hiddenvuln, args.only_exploits)

    # Display results
    if len([filtered]) > 0:
        print('[+] Found vulnerabilities')
        verb = 'Displaying'
        if args.outputfile:
            store_results(args.outputfile, filtered)
            verb = 'Saved'
            print_summary(filtered)
        else:
            print_results(filtered)
            print_summary(filtered)
            print()

        print('[+] Done. %s %d of the %d vulnerabilities found.' % (verb, len(filtered), len(found)))
    else:
        print('[-] No vulnerabilities found\n')


def load_defintions(definitions):
    with zipfile.ZipFile(definitions, "r") as definitionszip:
        files = definitionszip.namelist()

        # CVEs_yyyyMMdd.csv
        # DatePosted,CVE,BulletinKB,Title,AffectedProduct,AffectedComponent,Severity,Impact,Supersedes,Exploits
        cves = list(filter(lambda f: f.startswith('CVEs'), files))
        cvesfile = cves[0]
        date = cvesfile.split('.')[0].split('_')[1]
        f = io.TextIOWrapper(definitionszip.open(cvesfile, 'r'))
        cves = csv.DictReader(f, delimiter=str(','), quotechar=str('"'))

        # Version_X.XX.txt
        versions = list(filter(lambda f: f.startswith('Version'), files))
        versionsfile = versions[0]
        dbversion = float(re.search('Version_(.*)\.txt', versionsfile, re.MULTILINE | re.IGNORECASE).group(1))

        if dbversion > VERSION:
            raise WesException(
                'Definitions require at least version %.2f of wes.py. '
                'Please update using wes.py --update-wes.' % dbversion)

        return cves, date


def apply_display_filters(filtered, found, hiddenvulns, only_exploits):
    # --hide 'Product 1' 'Product 2'
    hiddenvulns = list(map(lambda s: s.lower(), hiddenvulns))
    filtered = []
    for cve in found:
        add = True
        for hidden in hiddenvulns:
            if hidden in cve['AffectedComponent'].lower() or hidden in cve['AffectedProduct'].lower():
                add = False
                break
        if add:
            filtered.append(cve)

    # --exploits-only
    if only_exploits:
        filtered = list(filter(lambda res: res['Exploits'], filtered))

    return filtered


def determine_missing_patches(productfilter, cves, hotfixes):
    # Filter CVEs that are applicable to this system
    filtered = []

    for cve in cves:
        if productfilter in cve['AffectedProduct']:
            cve['Relevant'] = True

            filtered.append(cve)

            if cve['Supersedes']:
                hotfixes.append(cve['Supersedes'])

    # Collect patches that are already superseeded and
    # merge these with the patches found installed on the system
    hotfixes = set(hotfixes)

    marked = set()
    for hotfix in hotfixes:
        mark_superseeded_hotfix(filtered, hotfix, marked)

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

    return filtered, found


def determine_product(systeminfo):
    systeminfo = charset_convert(systeminfo)

    # OS Version
    regex_version = re.compile(r'.*?:\s+((\d+\.?)+) ((Service Pack (\d)|N/A|.+) )?\w+ (\d+).*',
                               re.MULTILINE | re.IGNORECASE)
    systeminfo_matches = regex_version.findall(systeminfo)
    if len(systeminfo_matches) == 0:
        raise WesException('Not able to detect OS version based on provided input file')

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
        raise WesException('Failed assessing Windows version {}'.format(win))

    return productfilter, win, mybuild, version, arch, hotfixes


def mark_superseeded_hotfix(filtered, superseeded, marked):
    # Locate all CVEs for KB
    for ssitem in superseeded.split(';'):
        foundSuperseeded = filter(lambda cve: cve['Relevant'] and cve['BulletinKB'] == ssitem, filtered)
        for ss in foundSuperseeded:
            ss['Relevant'] = False

            # In case there is a child, recurse (depth first)
            if ss['Supersedes'] and ss['Supersedes'] not in marked:
                marked.add(ss['Supersedes'])
                mark_superseeded_hotfix(filtered, ss['Supersedes'], marked)


def print_summary(results):
    grouped = Counter([r['BulletinKB'] for r in results])
    print('[+] Missing patches: %d' % len(grouped))
    for line in grouped.most_common():
        kb = line[0]
        number = line[1]
        print('    - KB%s: patches %s %s' % (kb, number, 'vulnerabilty' if number == 1 else 'vulnerabilities'))


def print_results(results):
    print()
    for res in results:
        exploits = res['Exploits'] if 'Exploits' in res else ''
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


def store_results(outputfile, results):
    print('[+] Writing %d results to %s' % (len(results), outputfile))
    with open(outputfile, 'w', newline='') as f:
        header = list(results[0].keys())
        header.remove('Supersedes')
        writer = csv.DictWriter(f, fieldnames=header, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for r in results:
            del r['Supersedes']
            writer.writerow(r)


def check_file_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('File \'%s\' does not exist.' % value)

    return value


def check_definitions_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('Definitions file \'%s\' does not exist. Try running %s --update first.' % (value, FILENAME))

    return value


def parse_arguments():
    examples = r'''examples:
  Download latest definitions
  {0} --update
  {0} -u

  Determine vulnerabilities
  {0} systeminfo.txt

  Determine vulnerabilities and output to file
  {0} systeminfo.txt --output vulns.csv
  {0} systeminfo.txt -o vulns.csv

  Determine vulnerabilities explicitly specifying KBs to reduce false-positives
  {0} systeminfo.txt --patches KB4345421 KB4487017
  {0} systeminfo.txt -p KB4345421 KB4487017

  Determine vulnerabilities explicitly specifying definitions file
  {0} systeminfo.txt C:\tmp\mydefs.zip

  List only vulnerabilities with exploits, excluding Edge and Flash
  {0} systeminfo.txt --exploits-only --hide "Internet Explorer" Edge Flash
  {0} systeminfo.txt -e --hide "Internet Explorer" Edge Flash

  Download latest version of WES-NG
  {0} --update-wes
'''.format(FILENAME)

    parser = argparse.ArgumentParser(
        description=BANNER,
        add_help=False,
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Update definitions
    parser.add_argument('-u', '--update', dest='perform_update', action='store_true', help='Download latest list of CVEs')
    args, xx = parser.parse_known_args()
    if args.perform_update:
        return args

    # Update application
    parser.add_argument('--update-wes', dest='perform_wesupdate', action='store_true', help='Download latest version of wes.py')
    args, xx = parser.parse_known_args()
    if args.perform_wesupdate:
        return args

    # Options
    parser.add_argument('systeminfo', action='store', type=check_file_exists, help='Specify systeminfo.txt file')
    parser.add_argument('definitions', action='store', nargs='?', type=check_definitions_exists, default='definitions.zip', help='List of known vulnerabilities (default: definitions.zip)')
    parser.add_argument('-p', '--patches', dest='installedpatch', nargs='+', default='', help='Manually specify installed patches in addition to the ones listed in the systeminfo.txt file')
    parser.add_argument('-e', '--exploits-only', dest='only_exploits', action='store_true', help='Show only vulnerabilities with known exploits')
    parser.add_argument('--hide', dest='hiddenvuln', nargs='+', default='', help='Hide vulnerabilities of for example Adobe Flash Player and Microsoft Edge')
    parser.add_argument('-o', '--output', action='store', dest='outputfile', nargs='?', help='Store results in a file')
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')

    # Always show full help when no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    return parser.parse_args()


if __name__ == '__main__':
    main()
