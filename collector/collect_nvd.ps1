# Instructions
# 1. Execute the collect_bulletin.ps1 and collect_msrc.ps1 to collect the latest Microsoft patches
# 2. Execute the script to enrich the BulletinSearch.xlsx and MSRC CVEs with Exploit-DB links

"Start: {0}" -f [DateTime]::Now

# Create temporary directory for JSON files
$NVDPath = "$env:TMP\NVD"
New-Item -ItemType Directory $NVDPath -ErrorAction SilentlyContinue | Out-Null

"[+] Downloading NVD JSON updates"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
for($year = 2002; $year -le [DateTime]::Now.Year; $year++)
{
    $outfile = "$NVDPath\nvdcve-1.0-$year.json.zip"
    wget "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-$year.json.zip" -OutFile $outfile
    Expand-Archive $outfile -DestinationPath $NVDPath -Force
    Remove-Item $outfile
}

"[+] Extracting ExploitDB links from NVD databases"
$exploits = @()
for($year = 2002; $year -le [DateTime]::Now.Year; $year++)
{
    # Status update for each year
    "- $year"

    # Load JSON in memory
    $json = (gc "$NVDPath\nvdcve-1.0-$year.json" | ConvertFrom-Json)

    # Iterate over CVEs
    foreach($cve in $json.CVE_Items)
    {
        # Only focus on Microsoft vulnerabilities
        $vendors = ($cve.cve.affects.vendor.vendor_data.vendor_name) -split "`r`n"
        if($vendors -notcontains "microsoft")
            { continue }

        # Extract Exploit-DB links
        $edb = @($cve.cve.references.reference_data | ? refsource -EQ "EXPLOIT-DB" | select -expand url) -join ", "
        
        # Skip if no exploit available
        if($edb -eq "")
            { continue }

        $exploits += [PSCustomObject]@{
            "CVE"=$cve.cve.CVE_data_meta.ID;
            "Exploits"=$edb
        }
    }

    # Cleanup json
    Remove-Item "$NVDPath\nvdcve-1.0-$year.json"
}

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
$exploits = $exploits | ? Exploits -ne $null
$total = $exploits | measure | select -expand Count
$counter = 1

foreach($exploit in $exploits)
{
    # Find Bulletin/MSRC matches that have a matching CVE
    $matches = $CVEs | ? CVE -eq $exploit.CVE

    # Add exploit link(s) to matching CVEs
    $matches | % { $_.Exploits = $exploit.Exploits }

    $exploitcount = $exploit.Exploits -split ", " | measure | select -expand Count
    $matchcount = $matches | measure | select -expand Count

    # Report status
    $status = "[{0:000}/{1:000}] {2} - " -f $counter,$total,$exploit.CVE
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
#$cve_bulletin | Export-Clixml "CVEs.xml"

"[+] Writing enriched CVEs to CVEs.csv"
$CVEs | Export-Csv -NoTypeInformation -Encoding ASCII "CVEs.csv"

"[+] Packing CVEs.csv to CVEs.zip"
Compress-Archive -LiteralPath .\CVEs.csv -CompressionLevel Optimal -DestinationPath CVEs.zip

"[+] Done!"
"End: {0}" -f [DateTime]::Now