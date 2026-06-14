<#
Author: Arris Huijgen - @bitsadmin
Website: https://github.com/bitsadmin
License: BSD 3-Clause
#>

$minwesversion = 0.94

"Start: {0}" -f [DateTime]::Now

# Prerequisites
if(-not (Test-Path "Bulletin.csv"))
{
	"[-] Bulletin.csv is missing. Execute collect_bulletin.ps1 first."
	exit
}
if(-not (Test-Path "MSRC.csv"))
{
	"[-] MSRC.csv is missing. Execute collect_msrc.ps1 first."
	exit
}
if(-not (Test-Path "NVD.csv"))
{
	"[-] NVD.csv is missing. Execute collect_nvd.ps1 first."
	exit
}
if(-not (Test-Path "EDB.csv"))
{
	"[-] EDB.csv is missing. Execute collect_edb.ps1 first."
	exit
}

# Normalizes an exploit link so that equivalent links are deduplicated, e.g.
# https://www.exploit-db.com/exploits/38796/ and https://exploit-db.com/exploits/38796
# are recognized as the same link.
function Get-NormalizedLink([string]$link)
{
    $normalized = $link.Trim()
    # Drop scheme
    $normalized = $normalized -replace '^https?://', ''
    # Drop leading www.
    $normalized = $normalized -replace '^www\.', ''
    # Drop trailing slashes
    $normalized = $normalized.TrimEnd('/')
    return $normalized.ToLowerInvariant()
}

"[+] Loading NVD and Exploit-DB exploit links"
$nvd = Import-Csv -Encoding utf8 "NVD.csv"
$edb = Import-Csv -Encoding utf8 "EDB.csv"

# Merge both sources into a single CVE -> exploit links lookup
$exploitmap = @{}
foreach($entry in @($nvd) + @($edb))
{
    $cve = $entry.CVE
    if([string]::IsNullOrWhiteSpace($cve))
        { continue }

    if(-not $exploitmap.ContainsKey($cve))
    {
        $exploitmap[$cve] = [PSCustomObject]@{
            "Links"=[System.Collections.Generic.List[string]]::new();
            "Seen"=[System.Collections.Generic.HashSet[string]]::new()
        }
    }

    # Each source stores its links as a ", " separated string
    foreach($link in @($entry.Exploits -split ", "))
    {
        $link = $link.Trim()
        if($link -eq "")
            { continue }

        # Deduplicate based on the normalized form of the link
        $key = Get-NormalizedLink $link
        if($exploitmap[$cve].Seen.Add($key))
            { $exploitmap[$cve].Links.Add($link) }
    }
}

# Convert lookup into a list of exploit records (CVEs in ascending order)
$exploits = foreach($cve in ($exploitmap.Keys | Sort-Object))
{
    [PSCustomObject]@{
        "CVE"=$cve;
        "Exploits"=($exploitmap[$cve].Links -join ", ")
    }
}

"[+] Merging BulletinSearch and MSRC CSVs"
$cves_bulletin = Import-Csv -Encoding utf8 "Bulletin.csv"
$cves_msrc = Import-Csv -Encoding utf8 "MSRC.csv"
$CVEs = $cves_bulletin + $cves_msrc # TODO, check for overlapping records

"[+] Complementing Bulletin/MSRC dataset"
$CVEs | Add-Member -NotePropertyName "Exploits" -NotePropertyValue $null

# Filter CVEs that have corresponding exploits
$total = ($exploits | Measure-Object).Count
$counter = 1

foreach($exploit in $exploits)
{
    # Find Bulletin/MSRC matches that have a matching CVE
    $found = $CVEs | Where-Object CVE -eq $exploit.CVE

    # Add exploit link(s) to matching CVEs
    $found | ForEach-Object { $_.Exploits = $exploit.Exploits }

    $exploitcount = ($exploit.Exploits -split ", " | Measure-Object).Count
    $matchcount = ($found | Measure-Object).Count

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
$customcsv = Get-ChildItem Custom_*.csv | Select-Object -expand Name
"[+] Writing minimum required version number to $outversion"
New-Item $outversion -Type File -Value ("This definition file requires you to at least use wes version {0}`r`n`r`nDownload the latest version from https://github.com/bitsadmin/wesng`r`n" -f $wesver) | Out-Null
"[+] Packing files into definitions.zip"
Compress-Archive -LiteralPath $outcsv,$customcsv,$outversion -CompressionLevel Optimal -DestinationPath ..\definitions.zip -Force
Remove-Item $outcsv,$outversion

"[+] Done!"
"End: {0}" -f [DateTime]::Now
