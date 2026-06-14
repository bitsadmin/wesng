<#
Author: Arris Huijgen - @bitsadmin
Website: https://github.com/bitsadmin
License: BSD 3-Clause
#>

"Start: {0}" -f [DateTime]::Now

# Create temporary directory for JSON files
$NVDPath = "$env:TMP\NVD"
New-Item -ItemType Directory $NVDPath -ErrorAction SilentlyContinue | Out-Null

"[+] Downloading NVD JSON updates"
# Source: https://nvd.nist.gov/vuln/data-feeds
for($year = 2002; $year -le [DateTime]::Now.Year; $year++)
{
    $outfile = "$NVDPath\nvdcve-2.0-$year.json.zip"
    Invoke-WebRequest "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$year.json.zip" -OutFile $outfile
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
    $json = (Get-Content -Encoding utf8 "$NVDPath\nvdcve-2.0-$year.json" | ConvertFrom-Json)

    # Iterate over CVEs
    foreach($cve in $json.vulnerabilities.cve)
    {
        # Only focus on Microsoft vulnerabilities
        $mscve = $false
        $cpes = $cve.configurations.nodes.cpeMatch.criteria
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
        $edb = @($cve.references | Where-Object { $_.tags -contains 'Exploit' } | Select-Object -Unique -ExpandProperty url) -join ", "
        
        # Skip if no exploit available
        if($edb -eq "")
            { continue }

        $exploits += [PSCustomObject]@{
            "CVE"=$cve.id;
            "Exploits"=$edb
        }
    }

    # Cleanup json
    Remove-Item "$NVDPath\nvdcve-2.0-$year.json"
}

# Remove NVD directory
Remove-Item -Recurse $NVDPath

"[+] Storing list of CVEs and Exploit-DB links"
# DEBUG
#$exploits | Export-Clixml "NVD.xml"
$exploits | Export-Csv -NoTypeInformation -Encoding ASCII "NVD.csv"

"[+] Done! Run collect_merge.ps1 to enrich the Bulletin/MSRC dataset."
"End: {0}" -f [DateTime]::Now