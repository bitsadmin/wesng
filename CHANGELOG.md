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
