<#
Author: Arris Huijgen - @bitsadmin
Website: https://github.com/bitsadmin
License: BSD 3-Clause
#>

# Instructions
# 1. Execute collect_bulletin.ps1, this only needs to be performed once as this source is not updated anymore
# 2. Execute collect_msrc.ps1 to collect the latest Microsoft patches from MSRC
# 2. Execute collect_nvd.ps1 to enrich the BulletinSearch.xlsx and MSRC CVEs with exploit links

$minwesversion = 0.94

"Start: {0}" -f [DateTime]::Now

# Create temporary directory for JSON files
$NVDPath = "$env:TMP\NVD"
New-Item -ItemType Directory $NVDPath -ErrorAction SilentlyContinue | Out-Null

"[+] Downloading NVD JSON updates"
# Source: https://nvd.nist.gov/vuln/data-feeds
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
for($year = 2002; $year -le [DateTime]::Now.Year; $year++)
{
    $outfile = "$NVDPath\nvdcve-1.1-$year.json.zip"
    wget "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$year.json.zip" -OutFile $outfile
    Expand-Archive $outfile -DestinationPath $NVDPath -Force
    Remove-Item $outfile
}

"[+] Extracting exploit links from NVD databases"
$exploits = @()
for($year = 2002; $year -le [DateTime]::Now.Year; $year++)
{
    # Status update for each year
    "- $year"

    # Load JSON in memory
    $json = (gc "$NVDPath\nvdcve-1.1-$year.json" | ConvertFrom-Json)

    # Iterate over CVEs
    foreach($cve in $json.CVE_Items)
    {
        # Only focus on Microsoft vulnerabilities
        $mscve = $false
        $cpes = $cve.configurations.nodes.cpe_match.cpe23Uri + $cve.configurations.nodes.children.cpe_match.cpe23Uri
        foreach($cpe in $cpes)
        {
            if($cpe -like '*microsoft*')
            {
                $mscve = $true
                break
            }
        }
        if(-not $mscve)
            { continue }

        # Extract Exploit-DB and other exploit links
        $edb = @($cve.cve.references.reference_data | ? { $_.refsource -EQ "EXPLOIT-DB" -or $_.tags -contains 'Exploit' } | select -expand url) -join ", "
        
        # Skip if no exploit available
        if($edb -eq "")
            { continue }

        $exploits += [PSCustomObject]@{
            "CVE"=$cve.cve.CVE_data_meta.ID;
            "Exploits"=$edb
        }
    }

    # Cleanup json
    Remove-Item "$NVDPath\nvdcve-1.1-$year.json"
}

# Remove NVD directory
Remove-Item -Recurse $NVDPath

"[+] Storing list of CVEs and Exploit-DB links"
# DEBUG
#$exploits | Export-Clixml "NVD.xml"
$exploits | Export-Csv -NoTypeInformation -Encoding ASCII "NVD.csv"

"[+] Merging BulletinSearch and MSRC CSVs"
$cves_bulletin = Import-Csv "Bulletin.csv"
$cves_msrc = Import-Csv "MSRC.csv"
$CVEs = $cves_bulletin + $cves_msrc # TODO, check for overlapping records

"[+] Complementing Bulletin/MSRC dataset"
# DEBUG
#$exploits = Import-Clixml "NVD.xml"
$CVEs | Add-Member -NotePropertyName "Exploits" -NotePropertyValue $null

# Filter CVEs that have corresponding exploits
$total = $exploits | measure | % Count
$counter = 1

foreach($exploit in $exploits)
{
    # Find Bulletin/MSRC matches that have a matching CVE
    $matches = $CVEs | ? CVE -eq $exploit.CVE

    # Add exploit link(s) to matching CVEs
    $matches | % { $_.Exploits = $exploit.Exploits }

    $exploitcount = $exploit.Exploits -split ", " | measure | % Count
    $matchcount = $matches | measure | % Count

    # Report status
    $status = "[{0:0000}/{1:0000}] {2} - " -f $counter,$total,$exploit.CVE
    if($exploitcount -eq 1)
    { $status += "Added 1 exploit" }
    else
    { $status += "Added {0} exploits" -f $exploitcount }
    if($matchcount -eq 1)
    { $status += " to 1 record" }
    else
    { $status += " to {0} records" -f $matchcount }
    $status
    
    $counter++
}

# DEBUG
#$CVEs | Export-Clixml "CVEs.xml"

# Output
$outcsv = "CVEs_{0}.csv" -f [DateTime]::Now.ToString("yyyyMMdd")
"[+] Writing enriched CVEs to $outcsv"
$CVEs | Export-Csv -NoTypeInformation -Encoding ASCII $outcsv
$wesver = $minwesversion.ToString("0.00", [System.Globalization.CultureInfo]::InvariantCulture)
$outversion = "Version_{0}.txt" -f $wesver
$customcsv = gci Custom_*.csv | select -expand Name
"[+] Writing minimum required version number to $outversion"
New-Item $outversion -Type File -Value ("This definition file requires you to at least use wes version {0}`r`n`r`nDownload the latest version from https://github.com/bitsadmin/wesng`r`n" -f $wesver) | Out-Null
"[+] Packing files into definitions.zip"
Compress-Archive -LiteralPath $outcsv,$customcsv,$outversion -CompressionLevel Optimal -DestinationPath definitions.zip -Force
Remove-Item $outcsv,$outversion

"[+] Done!"
"End: {0}" -f [DateTime]::Now