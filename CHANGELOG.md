# Version 1.03
- Support for 21H2 of Windows 10, Windows 11 and Windows Server 2022

# Version 1.02
- Support for Windows 11 and Windows Server 2022
- Various minor improvements

# Version 1.00
- Added missingkbs.vbs to use Windows Update to identify missing patches
- Added support for 'wmic qfe' output
- Added option to manually specify the Operating System
- Added support for colored output using --color or -c (thanks to wrighterase)
- Various minor improvements

# Version 0.98
- Microsoft Update Catalog lookup feature by Dominic Breuker

# Version 0.97
- Resolved exception when using --output with Python 2
- Removed legacy definitions file (CVEs.zip)

# Version 0.96
- Support for Windows 10 Redstone 6 (1903)
- Added option to filter on severity 
- Fixup for French systeminfo file

# Version 0.95
## wes.py
**New features**
- Support for manually specified updates in definitions.zip file
- Feature to remove duplicate results in case of Windows Server

**Improvements**
- Extended debugging supersedes functionality
- Cleanup of buildnumbers
- Added title field to console results
- Bugfix where in case a Windows version without Service Packs was provided, vulnerabilities of that Windows version _with_ Service Packs would be listed
- Some minor improvements

## collector
- Added support to include manually specified updates in definitions.zip file
- Added csv with manual improvements to the MSRC/Bulletin Excel lists containing:
  - Services Packs
  - MS17-010 (EternalBlue) patches for all operating systems


# Version 0.942
**New features**
- Support for 'wmic qfe' output in case the list of KBs in the systeminfo output is cut off
- Parameter to use the most recent KB installed as reference point to filter out all vulnerabilities of KBs prior this date
- Parameter to show version
- (Hidden) flag to debug supersedes

**Improvements**
- Added comments to the code for improved readability
- Some minor improvements


# Version 0.94
## wes.py
**New features**
- Updated database format:
  - Filename of new format: definitions.zip
  - The CVEs file won't be extracted to disk but instead be directly read from the zip which greatly reduces the on-disk size of WES-NG.
  - The database format now contains the date at which the definitions have been created and a version number in case the database format will be updated again in the future. In that case the user will be informed to update wes.py tool.
  - Legacy updates file (CVEs.zip) will still be maintained for a while for whoever is still using a previous version of WES-NG.
- Update to the latest version of wes.py using the `--update-wes` parameter.
- Output shows summary of missing patches and the number of vulnerabilities this patch would patch.
- Option to output to a .csv file instead of to the screen using the `--output` or `-o` parameter, for example `-o vulns.csv`.
- Manually specify KBs that have been installed (or should be ignored) using the `--patches` or `-p` parameter, for example `-p KB4345421 KB4487017`. See (this)[/todo] article on how to use this feature to reduce false-positives.

**Additionally**
- For readability restructured code into separate functions.
- Bugfix in case a record would supersede multiple other records, it would not correctly be processed.
- Added a banner so when the wes.py output is redirected to a file, it is clear which version of WES-NG was used.
- Various minor changes and fixes.

## collector
- collect_bulletin: Merge multiple supersedes instead of splitting them up
- collect_msrc: Bugfix for multiple supersedes
- collect_nvd: Added support for outputting the new definitions.zip format
