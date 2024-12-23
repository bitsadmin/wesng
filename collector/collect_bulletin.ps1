<#
Author: Arris Huijgen - @bitsadmin
Website: https://github.com/bitsadmin
License: BSD 3-Clause
#>

# Instructions
# 1. Install the ImportExcel module using: Install-Module ImportExcel
# 2. Execute the script and wait for the Bulletin.csv file to be created

"Start: {0}" -f [DateTime]::Now
"[+] Downloading BulletinSearch.xlsx"
$bulletinxlsx = "$env:TMP\BulletinSearch.xlsx"
# Source: https://www.microsoft.com/download/details.aspx?id=36982
Invoke-WebRequest https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx -OutFile $bulletinxlsx

"[+] Loading Excel"
$xlsx = Import-Excel $bulletinxlsx -HeaderName DatePosted,BulletinId,BulletinKB,Severity,Impact,Title,AffectedProduct,ComponentKB,AffectedComponent,Impact2,Severity2,Supersedes,Reboot,CVEs

"[+] Processing Excel file"
$cve_bulletin = @()
$total = $xlsx | Measure-Object | Select-Object -expand Count
$counter = 1

# Parse all lines in xlsx
foreach($line in $xlsx)
{
    # Statusupdate every 1000 lines
    if($counter % 1000 -eq 0 -or $counter -eq $total)
    {
        "- Processed {0:00000}/{1:00000}" -f $counter,$total
    }

    $DatePosted = [datetime]::FromOADate($line.DatePosted).ToString("yyyyMMdd")
    $CVEs = $line.CVEs -split ","
    $ComponentKB = $line.ComponentKB
    $Title = $line.Title
    $AffectedProduct = $line.AffectedProduct.Replace("2016 for x64-based Systems", "2016") # Fixup, there is no x86 version of Windows Server 2016
    $AffectedComponent = $line.AffectedComponent
    $Severity = $line.Severity
    $Impact = $line.Impact
    $Supersedes = $line.Supersedes -split { $_ -eq ";" -or $_ -eq "," } | ForEach-Object { $_ -replace '.*?(\d{6,}).*','$1' }

    if($null -eq $Supersedes)
    {
        $Supersedes = @("")
    }

    # Iterate over CVEs
    foreach($cve in $CVEs)
    {

        $cve_bulletin += [PSCustomObject]@{
            DatePosted=$DatePosted;
            CVE=$cve.Trim();
            BulletinKB=$ComponentKB;
            Title=$Title;
            AffectedProduct=$AffectedProduct;
            AffectedComponent=$AffectedComponent;
            Severity=$Severity;
            Impact=$Impact;
            Supersedes=$Supersedes -join ";"
        }
    }

    $counter++
}

# DEBUG
#$cve_bulletin | Export-Clixml "Bulletin.xml"
#$cve_bulletin = Import-Clixml "Bulletin.xml"

"[+] Writing Bulletin CVEs to file"
$cve_bulletin | Export-Csv -NoTypeInformation -Encoding utf8 "Bulletin.csv"

"[+] Cleanup"
Remove-Item $bulletinxlsx

"[+] Done!"
"End: {0}" -f [DateTime]::Now