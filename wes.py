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

import copy


# Python 2 compatibility
if sys.version_info.major == 2:
    from urllib import urlretrieve
    ModuleNotFoundError = ImportError
else:
    from urllib.request import urlretrieve


# Check availability of the chardet library:
# "The universal character encoding detector"
try:
    import chardet
    # Using chardet library to determine the approperiate encoding
    def charset_convert(data):
        encoding = chardet.detect(data)
        data = data.decode(encoding['encoding'], 'ignore')

        if sys.version_info.major == 2:
            data = data.encode(sys.getfilesystemencoding())

        return data

except (ImportError, ModuleNotFoundError):
    # Parse everything as ASCII
    def charset_convert(data):
        data = data.decode('ascii', 'ignore')

        if sys.version_info.major == 2:
            data = data.encode(sys.getfilesystemencoding())

        return data

    logging.warning(
        'chardet module not installed. In case of encoding '
        'errors, install chardet using: pip{} install chardet'.format(sys.version_info.major))


class WesException(Exception):
    pass


# Applictation details
VERSION = 0.98
RELEASE = ''
WEB_URL = 'https://github.com/bitsadmin/wesng/'
BANNER = 'Windows Exploit Suggester %.2f%s ( %s )' % (VERSION, RELEASE, WEB_URL)
FILENAME = 'wes.py'

# Mapping table between build numbers and versions to correctly identify
# the Windows 10/Server 2016 version specified in the systeminfo output
buildnumbers = OrderedDict([
    (10240, 1507),
    (10586, 1511),
    (14393, 1607),
    (15063, 1703),
    (16299, 1709),
    (17134, 1803),
    (17763, 1809),
    (18362, 1903),
    (18363, 1909),
    (19041, 2004)
])


def main():
    args = parse_arguments()

    # Application banner
    print(BANNER)

    # Update definitions
    if hasattr(args, 'perform_update') and args.perform_update:
        print('[+] Updating definitions')
        urlretrieve('https://raw.githubusercontent.com/bitsadmin/wesng/master/definitions.zip', 'definitions.zip')
        cves, date = load_definitions('definitions.zip')
        print('[+] Obtained definitions created at %s' % date)
        return

    # Update application
    if hasattr(args, 'perform_wesupdate') and args.perform_wesupdate:
        print('[+] Updating wes.py')
        urlretrieve('https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py', 'wes.py')
        print('[+] Updated to the latest version. Relaunch wes.py to use.')
        return

    # Show tree of supersedes (for debugging purposes)
    if hasattr(args, 'debugsupersedes') and args.debugsupersedes:
        cves, date = load_definitions('definitions.zip')
        productfilter = args.debugsupersedes[0]
        supersedes = args.debugsupersedes[1:]
        filtered = []
        for cve in cves:
            if productfilter not in cve['AffectedProduct']:
                continue

            filtered.append(cve)

        debug_supersedes(filtered, supersedes, 0, args.verbosesupersedes)
        return

    # Show version
    if hasattr(args, 'showversion') and args.showversion:
        cves, date = load_definitions('definitions.zip')
        print('Wes.py version: %.3f' % VERSION)
        print('Database version: %s' % date)
        return

    # Parse encoding of systeminfo.txt input
    print('[+] Parsing systeminfo output')
    systeminfo_data = open(args.systeminfo, 'rb').read()
    try:
        productfilter, win, mybuild, version, arch, hotfixes = determine_product(systeminfo_data)
    except WesException as e:
        print('[-] ' + str(e))
        exit(1)

    # Parse optional qfe.txt input file
    if args.qfefile:
        print('[+] Parsing quick fix engineering (qfe) output')
        qfe_data = open(args.qfefile, 'rb').read()
        try:
            qfe_data = charset_convert(qfe_data)
            qfe_patches = get_hotfixes(qfe_data)
            hotfixes = list(set(hotfixes + qfe_patches))
        except WesException as e:
            print('[-] ' + str(e))
            exit(1)

    # Add explicitly specified patches
    manual_hotfixes = list(set([patch.upper().replace('KB', '') for patch in args.installedpatch]))

    # Display summary
    info = '''[+] Operating System
    - Name: %s
    - Generation: %s
    - Build: %s
    - Version: %s
    - Architecture: %s''' % (productfilter, win, mybuild, version, arch)
    if hotfixes:
        info += '\n    - Installed hotfixes (%d): %s' % (len(hotfixes), ', '.join(['KB%s' % kb for kb in hotfixes]))
    else:
        info += '\n    - Installed hotfixes: None'
    if manual_hotfixes:
        info += '\n    - Manually specified hotfixes (%d): %s' % (len(manual_hotfixes),
                                                                  ', '.join(['KB%s' % kb for kb in manual_hotfixes]))
    print(info)

    # Append manually specified KBs to list of hotfixes
    hotfixes = list(set(hotfixes + manual_hotfixes))
    hotfixes_orig = copy.deepcopy(hotfixes)

    # Load definitions from definitions.zip (default) or user-provided location
    print('[+] Loading definitions')
    try:
        cves, date = load_definitions(args.definitions)
        print('    - Creation date of definitions: %s' % date)

        print('[+] Determining missing patches')
        filtered, found = determine_missing_patches(productfilter, cves, hotfixes)
    except WesException as e:
        print('[-] ' + str(e))
        exit(1)

    # If -d parameter is specified, use the most recent patch installed as
    # reference point for the system's patching status
    if args.usekbdate:
        print('[+] Filtering old vulnerabilities')
        recentkb = get_most_recent_kb(found)
        if recentkb:
            print('    - Most recent KB installed is KB%s released at %s\n'
                  '    - Filtering all KBs released before this date' % (recentkb['BulletinKB'], recentkb['DatePosted']))
            recentdate = int(recentkb['DatePosted'])
            found = list(filter(lambda kb: int(kb['DatePosted']) >= recentdate, found))

    if 'Windows Server' in productfilter:
        print('[+] Filtering duplicate vulnerabilities')
        found = filter_duplicates(found)

    # If specified, hide results containing the user-specified string
    # in the AffectedComponent and AffectedProduct attributes
    if args.hiddenvuln or args.only_exploits or args.impacts or args.severities:
        print('[+] Applying display filters')
        filtered = apply_display_filters(found, args.hiddenvuln, args.only_exploits, args.impacts, args.severities)
    else:
        filtered = found

    # If specified, lookup superseeding KBs in the Microsoft Update Catalog
    # and remove CVEs if a superseeding KB is installed.
    if args.muc_lookup:
        from muc_lookup import apply_muc_filter # ony import if necessary since it needs MechanicalSoup

        print("[+] Looking up superseeding hotfixes in the Microsoft Update Catalog")
        filtered = apply_muc_filter(filtered, hotfixes_orig)

    # Split up list of KBs and the potential Service Packs/Cumulative updates available
    kbs, sp = get_patches_servicepacks(filtered, cves, productfilter)

    # Display results
    if len(filtered) > 0:
        print('[+] Found vulnerabilities')
        verb = 'Displaying'
        if args.outputfile:
            store_results(args.outputfile, filtered)
            verb = 'Saved'
            print_summary(kbs, sp)
        else:
            print_results(filtered)
            print_summary(kbs, sp)
            print()
        print('[+] Done. %s %d of the %d vulnerabilities found.' % (verb, len(filtered), len(found)))
    else:
        print('[-] No vulnerabilities found\n')


# Load definitions.zip containing a CSV with vulnerabilities collected by the WES collector module
# and a file determining the minimum wes.py version the definitions are compatible with.
def load_definitions(definitions):
    with zipfile.ZipFile(definitions, 'r') as definitionszip:
        files = definitionszip.namelist()

        # Version_X.XX.txt
        versions = list(filter(lambda f: f.startswith('Version'), files))
        versionsfile = versions[0]
        dbversion = float(re.search('Version_(.*)\.txt', versionsfile, re.MULTILINE | re.IGNORECASE).group(1))

        if dbversion > VERSION:
            raise WesException(
                'Definitions require at least version %.2f of wes.py. '
                'Please update using wes.py --update-wes.' % dbversion)

        # CVEs_yyyyMMdd.csv
        # DatePosted,CVE,BulletinKB,Title,AffectedProduct,AffectedComponent,Severity,Impact,Supersedes,Exploits
        cvesfiles = list(filter(lambda f: f.startswith('CVEs'), files))
        cvesfile = cvesfiles[0]
        cvesdate = cvesfile.split('.')[0].split('_')[1]
        f = io.TextIOWrapper(definitionszip.open(cvesfile, 'r'))
        cves = csv.DictReader(filter(lambda row: row[0]!='#', f), delimiter=str(','), quotechar=str('"'))

        # Custom_yyyyMMdd.csv
        customfiles = list(filter(lambda f: f.startswith('Custom'), files))
        customfile = customfiles[0]
        #customdate = customfile.split('.')[0].split('_')[1]
        f = io.TextIOWrapper(definitionszip.open(customfile, 'r'))
        custom = csv.DictReader(filter(lambda row: row[0]!='#', f), delimiter=str(','), quotechar=str('"'))

        # Merge official and custom list of CVEs
        merged = [cve for cve in cves] + [c for c in custom]

        return merged, cvesdate


# Hide results based on filter(s) specified by the user. This can either be to only display results with
# public exploits, results with a given impact or results containing the user specified string(s) in
# the AffectedComponent or AffectedProduct attributes.
def apply_display_filters(found, hiddenvulns, only_exploits, impacts, severities):
    # --hide 'Product 1' 'Product 2'
    hiddenvulns = list(map(lambda s: s.lower(), hiddenvulns))
    impacts = list(map(lambda s: s.lower(), impacts))
    severities = list(map(lambda s: s.lower(), severities))
    filtered = []
    for cve in found:
        add = True
        for hidden in hiddenvulns:
            if hidden in cve['AffectedComponent'].lower() or hidden in cve['AffectedProduct'].lower():
                add = False
                break

        for impact in impacts:
            if not impact in cve['Impact'].lower():
                add = False
            else:
                add = True
                break

        for severity in severities:
            if not severity in cve['Severity'].lower():
                add = False
            else:
                add = True
                break

        if add:
            filtered.append(cve)

    # --exploits-only
    if only_exploits:
        filtered = list(filter(lambda res: res['Exploits'], filtered))

    return filtered


# Filter duplicate CVEs for the Windows Server operating systems which often have a
# 'Windows Server 2XXX' and a 'Windows Server 2XXX (Server Core installation)' CVE that are exactly the same
def filter_duplicates(found):
    cves = list(set([cve['CVE'] for cve in found]))
    newfound = []

    # Iterate over unique CVEs
    for cve in cves:
        coreresults = list(filter(lambda cr: cr['CVE'] == cve and 'Server Core' in cr['AffectedProduct'], found))

        # If no 'Server Core' results for CVE, just add all records matching the CVE
        if len(coreresults) == 0:
            normalresults = list(filter(lambda nr: nr['CVE'] == cve, found))
            for n in normalresults:
                newfound.append(n)
            continue

        # In case 'Server Core' records are found, identify matching non-core results
        for r in coreresults:
            regularcounterparts = list(filter(lambda c:
                                              'Server Core' not in c['AffectedProduct'] and
                                              c['CVE'] == r['CVE'] and
                                              c['BulletinKB'] == r['BulletinKB'] and
                                              c['Title'] == r['Title'] and
                                              c['AffectedComponent'] == r['AffectedComponent'] and
                                              c['Severity'] == r['Severity'] and
                                              c['Impact'] == r['Impact'] and
                                              c['Exploits'] == r['Exploits'], found))

            # If non-'Server Core' counterparts are found, add these
            if len(regularcounterparts) >= 1:
                for rc in regularcounterparts:
                    newfound.append(rc)
            # Otherwise, add the 'Server Core' CVE
            else:
                newfound.append(r)

    return newfound


# Filter CVEs that are applicable to this system
def determine_missing_patches(productfilter, cves, hotfixes):
    filtered = []

    # Product with a Service Pack
    if 'Service Pack' in productfilter:
        for cve in cves:
            if productfilter not in cve['AffectedProduct']:
                continue

            cve['Relevant'] = True
            filtered.append(cve)

            if cve['Supersedes']:
                hotfixes.append(cve['Supersedes'])
    # Make sure that if the productfilter does not contain a Service Pack, we don't list the versions of that OS
    # which include a Service Pack in the product name
    else:
        productfilter_sp = productfilter + ' Service Pack'
        for cve in cves:
            if productfilter not in cve['AffectedProduct'] or productfilter_sp in cve['AffectedProduct']:
                continue

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


# Function which recursively marks KBs as irrelevant whenever they are superseeded
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


# Determine Windows version based on the systeminfo input file provided
def determine_product(systeminfo):
    systeminfo = charset_convert(systeminfo)

    # Fixup for 7_sp1_x64_enterprise_fr_systeminfo_powershell.txt
    systeminfo = systeminfo.replace('\xA0', '\x20')

    # OS Version
    regex_version = re.compile(r'.*?((\d+\.?){3}) ((Service Pack (\d)|N\/\w|.+) )?[ -\xa5]+ (\d+).*', re.MULTILINE | re.IGNORECASE)
    systeminfo_matches = regex_version.findall(systeminfo)
    if len(systeminfo_matches) == 0:
        raise WesException('Not able to detect OS version based on provided input file')

    systeminfo_matches = systeminfo_matches[0]
    mybuild = int(systeminfo_matches[5])
    servicepack = systeminfo_matches[4]

    # OS Name
    win_matches = re.findall('.*?Microsoft[\(R\)]{0,3} Windows[\(R\)?]{0,3} ?(Serverr? )?(\d+\.?\d?( R2)?|XP|VistaT).*', systeminfo, re.MULTILINE | re.IGNORECASE)
    if len(win_matches) == 0:
        raise WesException('Not able to detect OS name based on provided input file')
    win = win_matches[0][1]

    # System Type
    archs = re.findall('.*?([\w\d]+?)-based PC.*', systeminfo, re.MULTILINE | re.IGNORECASE)
    if len(archs) > 0:
        arch = archs[0]
    else:
        logging.warning('Cannot determine system\'s architecture. Assuming x64')
        arch = 'x64'

    # Hotfix(s)
    hotfixes = get_hotfixes(systeminfo)

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
        productfilter = 'Windows %s for %s Systems' % (win, arch)
        if servicepack:
            productfilter += ' Service Pack %s' % servicepack
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
    # Even though in the definitions there is a distinction though between 2003 and 2003 R2, there are only around 50
    # KBs specificly for 2003 R2 (x86/x64) and almost 6000 KBs for 2003 (x86/x64)
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


# Extract hotfixes from provided text file
def get_hotfixes(text):
    hotfix_matches = re.findall('.*KB\d+.*', text, re.MULTILINE | re.IGNORECASE)
    hotfixes = []
    for match in hotfix_matches:
        hotfixes.append(re.search('.*KB(\d+).*', match, re.MULTILINE | re.IGNORECASE).group(1))

    return hotfixes


# Debugging feature to list hierarchy of superseeded KBs according to the definitions file
def debug_supersedes(cves, kbs, indent, verbose):
    for kb in kbs:
        # Determine KBs superseeded by provided KB
        foundkbs = list(filter(lambda k: k['BulletinKB'] == kb, cves))

        # Extract date and title
        titles = []
        for f in foundkbs:
            titles.append(f['Title'])
        titles = list(set(filter(None, titles)))
        titles.sort()

        kbdate = foundkbs[0]['DatePosted'] if foundkbs else '????????'
        kbtitle = titles[0] if titles else ''

        # Print
        indentstr = '  ' * indent
        print('[%.2d][%s] %s%s - %s' % (indent, kbdate, indentstr, kb.ljust(7, ' '), kbtitle))
        if verbose and len(titles) > 1:
            for t in titles[1:]:
                print('%s%s%s' % (indentstr, ' ' * 25, t))

        # Recursively iterate over KBs superseeded by the current KB
        supersedes = []
        for f in foundkbs:
            supersedes += f['Supersedes'].split(';')
        supersedes = list(set(filter(None, supersedes)))
        debug_supersedes(cves, supersedes, indent + 1, verbose)


# Split up list of KBs and the potential Service Packs/Cumulative updates available
def get_patches_servicepacks(results, cves, productfilter):
    # Extract available Service Packs (if any)
    sp = list(filter(lambda c: c['CVE'].startswith('SP'), results))
    if len(sp) > 0:
        sp = sp[0]  # There should only be one result

        # Only focus on OS + architecure, current service pack is not relevant
        productfilter = re.sub(' Service Pack \d', '', productfilter)

        # Determine service packs available for the OS and determine the latest version available
        servicepacks = list(filter(lambda c: c['CVE'].startswith('SP') and productfilter in c['AffectedProduct'], cves))
        lastpatch = get_last_patch(servicepacks, sp)

        # Remove service packs from regular KB output
        kbs = list(filter(lambda c: not c['CVE'].startswith('SP'), results))

        return kbs, lastpatch

    return results, None


# Obtain most recent patch tracing back recursively locating records which superseeded the provided record
def get_last_patch(servicepacks, kb):
    results = list(filter(lambda c: c['Supersedes'] == kb['BulletinKB'], servicepacks))

    if results:
        return get_last_patch(servicepacks, results[0])
    else:
        return kb


# Show summary at the end of results containing the number of patches and the most recent patch installed
def print_summary(kbs, sp):
    # Show missing KBs with number of vulnerabilites per KB
    grouped = Counter([r['BulletinKB'] for r in kbs])
    print('[+] Missing patches: %d' % len(grouped))
    for line in grouped.most_common():
        kb = line[0]
        number = line[1]
        print('    - KB%s: patches %s %s' % (kb, number, 'vulnerability' if number == 1 else 'vulnerabilities'))

    # Show in case a service pack is missing
    if sp:
        print('[+] Missing service pack')
        print('    - %s' % sp['Title'])

    # Latest KB
    if not kbs:
        return
    foundkb = get_most_recent_kb(kbs)
    print('''[+] KB with the most recent release date
    - ID: KB%s
    - Release date: %s''' % (foundkb['BulletinKB'], foundkb['DatePosted']))


# Obtain most recent KB from a dictionary of results
def get_most_recent_kb(results):
    dates = [int(r['DatePosted']) for r in results]
    if dates:
        date = str(max(dates))
        return list(filter(lambda kb: kb['DatePosted'] == date, results))[0]
    else:
        return None


# Output results of wes.py to screen
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

        print('''Date: %s
CVE: %s
KB: KB%s
Title: %s
Affected product: %s
Affected component: %s
Severity: %s
Impact: %s
%s: %s
''' % (res['DatePosted'], res['CVE'], res['BulletinKB'], res['Title'], res['AffectedProduct'], res['AffectedComponent'], res['Severity'], res['Impact'], label, value))


# Output results of wes.py to a .csv file
def store_results(outputfile, results):
    print('[+] Writing %d results to %s' % (len(results), outputfile))

    # Python 2 compatibility
    if sys.version_info.major == 2:
        f = open(outputfile, 'wb')
    else:
        f = open(outputfile, 'w', newline='')

    header = list(results[0].keys())
    header.remove('Supersedes')
    writer = csv.DictWriter(f, fieldnames=header, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for r in results:
        if 'Supersedes' in r:
            del r['Supersedes']
        writer.writerow(r)


# Validate file existence for user-provided arguments
def check_file_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('File \'%s\' does not exist.' % value)

    return value


# Validate file existence for definitions file
def check_definitions_exists(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('Definitions file \'%s\' does not exist. Try running %s --update first.' % (value, FILENAME))

    return value


# Specify arguments using for the argparse library
def parse_arguments():
    examples = r'''examples:
  Download latest definitions
  {0} --update
  {0} -u

  Determine vulnerabilities
  {0} systeminfo.txt
  
  Determine vulnerabilities using both systeminfo and qfe files
  {0} systeminfo.txt qfe.txt

  Determine vulnerabilities and output to file
  {0} systeminfo.txt --output vulns.csv
  {0} systeminfo.txt -o vulns.csv

  Determine vulnerabilities explicitly specifying KBs to reduce false-positives
  {0} systeminfo.txt --patches KB4345421 KB4487017
  {0} systeminfo.txt -p KB4345421 KB4487017
  
  Determine vulnerabilies filtering out out vulnerabilities of KBs that have been published before the publishing date of the most recent KB installed
  {0} systeminfo.txt --usekbdate
  {0} systeminfo.txt -d

  Determine vulnerabilities explicitly specifying definitions file
  {0} systeminfo.txt --definitions C:\tmp\mydefs.zip

  List only vulnerabilities with exploits, excluding IE, Edge and Flash
  {0} systeminfo.txt --exploits-only --hide "Internet Explorer" Edge Flash
  {0} systeminfo.txt -e --hide "Internet Explorer" Edge Flash

  Only show vulnerabilities of a certain impact
  {0} systeminfo.txt --impact "Remote Code Execution"
  {0} systeminfo.txt -i "Remote Code Execution"
  
  Only show vulnerabilities of a certain severity
  {0} systeminfo.txt --severity critical
  {0} systeminfo.txt -s critical
  
  Validate supersedence against Microsoft's online Update Catalog
  {0} systeminfo.txt --muc-lookup

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

    # Show version
    parser.add_argument('--version', dest='showversion', action='store_true', help='Show version information')
    args, xx = parser.parse_known_args()
    if args.showversion:
        return args

    # Debug supersedes: perform a check on the supersedence tree according to the definitions.zip
    # First argument is OS (as listed in the definitions) or an empty string for no filter, next arguments are 1 or more KBs.
    # The --verbose argument will have wes.py print all titles of KBs found instead of only the first title.
    # Example: wes.py --debug-supersedes "Windows Vista x64 Edition Service Pack 2" 3216916 --verbose
    parser.add_argument('--debug-supersedes', dest='debugsupersedes', nargs='+', default='', help=argparse.SUPPRESS)
    parser.add_argument('--verbose', dest='verbosesupersedes', action='store_true', help=argparse.SUPPRESS)
    args, xx = parser.parse_known_args()
    if args.debugsupersedes:
        return args

    # Options
    parser.add_argument('systeminfo', action='store', type=check_file_exists, help='Specify systeminfo.txt file')
    parser.add_argument('--definitions', action='store', nargs='?', type=check_definitions_exists, default='definitions.zip', help='Definitions zip file (default: definitions.zip)')
    parser.add_argument('qfefile', action='store', nargs='?', type=check_file_exists, help='Specify the file containing the output of the \'wmic qfe\' command')
    parser.add_argument('-p', '--patches', dest='installedpatch', nargs='+', default='', help='Manually specify installed patches in addition to the ones listed in the systeminfo.txt file')
    parser.add_argument('-d', '--usekbdate', dest='usekbdate', action='store_true', help='Filter out vulnerabilities of KBs published before the publishing date of the most recent KB installed')
    parser.add_argument('-e', '--exploits-only', dest='only_exploits', action='store_true', help='Show only vulnerabilities with known exploits')
    parser.add_argument('--hide', dest='hiddenvuln', nargs='+', default='', help='Hide vulnerabilities of for example Adobe Flash Player and Microsoft Edge')
    parser.add_argument('-i', '--impact', dest='impacts', nargs='+', default='', help='Only display vulnerabilities with a given impact')
    parser.add_argument('-s', '--severity', dest='severities', nargs='+', default='', help='Only display vulnerabilities with a given severity')
    parser.add_argument('-o', '--output', action='store', dest='outputfile', nargs='?', help='Store results in a file')
    parser.add_argument("--muc-lookup", dest="muc_lookup", action="store_true", help="Hide vulnerabilities if installed hotfixes are listed in the Microsoft Update Catalog as superseding hotfixes for the original BulletinKB",
    )
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')

    # Always show full help when no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        exit(1)

    return parser.parse_args()


if __name__ == '__main__':
    main()
