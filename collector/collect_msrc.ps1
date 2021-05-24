<#
Author: Arris Huijgen - @bitsadmin
Website: https://github.com/bitsadmin
License: BSD 3-Clause
#>

# Instructions
# 1. Install the MSRC module using: Install-Module MSRCSecurityUpdates -Force
# 2. Request your own API key via https://portal.msrc.microsoft.com/en-us/developer and paste it here:
$apikey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
# 3. Execute the script and wait for the MSRC.csv file to be created

# Import module
Import-Module MSRCSecurityUpdates

# Fetch MSRC CVRF documents
$dateformat = "hh:mm"
Set-MSRCApiKey -ApiKey $apikey
$msu = Get-MsrcSecurityUpdate
$docs = @()

"Start: {0}" -f [DateTime]::Now
"[+] Downloading documents from MSRC"
$i=1
foreach($secupdate in $msu)
{
    "- [{0:00}/{1:00}]: {2}" -f $i,$msu.Length,$secupdate.DocumentTitle
    $docs += Get-MsrcCvrfDocument -id $secupdate.ID
    $i++
}

# Sort documents chronologically
$docs = $docs | sort @{Expression={$_.DocumentTracking.InitialReleaseDate}}

# DEBUG
#$docs | Export-Clixml "MSRCdocs.xml"
#$docs = Import-Clixml "MSRCdocs.xml"

"[+] Processing MSRC documents"
$allProductIDS = @()
$cves_msrc = @()
$i = 1

# Monthly releases
foreach($doc in $docs)
{
    # Print current month to screen
    "- [{0:00}/{1:00}]: {2}" -f $i,$docs.Length,$doc.DocumentTitle.Value

    # Compile list of all products
    $allProductIDS += $doc.ProductTree.FullProductName

    # Iterate over CVEs per monthly release
    foreach($cve in $doc.Vulnerability)
    {
        $DatePosted = [System.Convert]::ToDateTime(($cve.RevisionHistory | select -Last 1).Date).ToString("yyyyMMdd")
        $CveID = $cve.CVE
        $Title = $cve.Title.Value
        $AffectedComponent = ($cve.Notes | select -Last 1).Title
        #$description = ($cve.Notes | ? Title -eq "Description" | select -expand Value) -replace "<p>","" -replace "</p>`n", " " -replace "`r", ""

        # Iterate over KBs per CVE
        foreach($kb in $cve.Remediations)
        {
            $BulletinKB = $kb.Description.Value
            $Supersedes = $kb.Supercedence -split {$_ -eq ";" -or $_ -eq "," -or $_ -eq " "} | ? { $_ -and $_ -inotlike '*MS*' }
            if($Supersedes -eq $null) { $Supersedes = @("") }

            # Iterate over products patched by the KB
            foreach($productid in $kb.ProductID)
            {
                $threats = $cve.Threats | ? ProductID -Contains $productid
                $Severity = ($threats | ? Type -EQ 3).Description.Value
                $Impact = ($threats | ? Type -EQ 0).Description.Value
                $AffectedProduct = $doc.ProductTree.FullProductName | ? ProductId -EQ $productid | select -expand Value
                
                # Fix-up for mistakes in the AffectedProduct and AffectedComponent fields
                $AffectedProduct = $AffectedProduct.TrimEnd() -replace '  ', ' '
                $AffectedComponent = $AffectedComponent.TrimEnd() -replace '  ', ' '
                
                $cves_msrc += [PSCustomObject]@{
                    DatePosted=$DatePosted;
                    CVE=$CveID;
                    BulletinKB=$BulletinKB;
                    Title=$Title;
                    AffectedProduct=$AffectedProduct;
                    AffectedComponent=$AffectedComponent;
                    Severity=$Severity;
                    Impact=$Impact;
                    Supersedes=$Supersedes -join ";"
                }
            }
        }
    }

    $i++
}

# DEBUG
#$cve_bulletin | Export-Clixml "MSRC.xml"
#$cve_bulletin = Import-Clixml "MSRC.xml"

"[+] {{{0}}} Writing CVEs from MSRC to file" -f [DateTime]::Now.ToString($dateformat)
$cves_msrc | Export-Csv -NoTypeInformation -Encoding ASCII "MSRC.csv"
"[+] Done!"
"End: {0}" -f [DateTime]::Now
