<#
Author: Arris Huijgen - @bitsadmin
Website: https://github.com/bitsadmin
License: BSD 3-Clause
#>

"Start: {0}" -f [DateTime]::Now

# Create temporary directory for the Exploit-DB CSV
$EDBPath = "$env:TMP\EDB"
New-Item -ItemType Directory $EDBPath -ErrorAction SilentlyContinue | Out-Null
$EDBFile = "$EDBPath\files_exploits.csv"

"[+] Downloading Exploit-DB files_exploits.csv"
# Source: https://gitlab.com/exploit-database/exploitdb
Invoke-WebRequest "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads&inline=false" -OutFile $EDBFile

"[+] Extracting exploit links from Exploit-DB database"
$edb = Import-Csv -Encoding utf8 $EDBFile

# Build a lookup of CVE -> Exploit-DB links
$exploitmap = @{}
$total = ($edb | Measure-Object).Count
$counter = 0
foreach($entry in $edb)
{
    $counter++

    if($counter % 1000 -eq 0)
        { "- [{0}/{1}]" -f $counter,$total }

    # Only collect Microsoft/Windows related exploits
    if($entry.description -notmatch '(Microsoft|Windows)')
        { continue }

    # Compile Exploit-DB link based on the id column
    $link = "https://exploit-db.com/exploits/{0}" -f $entry.id

    # Split the codes column by semicolon separator and keep only CVEs
    $cves = @($entry.codes -split ';' | Where-Object { $_ -like 'CVE-*' })

    foreach($cve in $cves)
    {
        $cve = $cve.Trim()
        if($cve -eq "")
            { continue }

        if(-not $exploitmap.ContainsKey($cve))
            { $exploitmap[$cve] = [System.Collections.Generic.List[string]]::new() }

        if(-not $exploitmap[$cve].Contains($link))
            { $exploitmap[$cve].Add($link) }
    }
}

# Convert lookup into a list of exploit records
$exploits = foreach($cve in $exploitmap.Keys)
{
    [PSCustomObject]@{
        "CVE"=$cve;
        "Exploits"=($exploitmap[$cve] -join ", ")
    }
}

# Remove EDB directory
Remove-Item -Recurse $EDBPath

"[+] Storing list of CVEs and Exploit-DB links"
# DEBUG
#$exploits | Export-Clixml "EDB.xml"
$exploits | Sort-Object CVE | Export-Csv -NoTypeInformation -Encoding ASCII "EDB.csv"

"[+] Done! Run collect_merge.ps1 to enrich the Bulletin/MSRC dataset."
"End: {0}" -f [DateTime]::Now
