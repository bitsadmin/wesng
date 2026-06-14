# Instructions
1. Execute `collect_bulletin.ps1`, this only needs to be performed once as its source (`BulletinSearch.xlsx`) is not updated anymore (produces `Bulletin.csv`)
2. Execute `collect_msrc.ps1` to collect the latest Microsoft patches from MSRC (produces `MSRC.csv`)
3. Execute `collect_nvd.ps1` to collect exploit links from NVD (produces `NVD.csv`)
4. Execute `collect_edb.ps1` to collect exploit links from Exploit-DB (produces `EDB.csv`)
5. Execute `merge.ps1` to merge `Bulletin.csv` and `MSRC.csv`, enrich it with the collected exploit links (`NVD.csv` and `EDB.csv`) and output `definitions.zip`

Run in PowerShell oneliner:
```powershell
Remove-Item ..\definitions.zip ; .\collect_msrc.ps1 ; .\collect_nvd.ps1 ; .\collect_edb.ps1 ; .\merge.ps1 ; .\push_definitions.ps1
```