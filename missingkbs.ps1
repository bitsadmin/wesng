<#
.SYNOPSIS
Compiles a list of missing KBs on the current system.

.DESCRIPTION
These missing KBs are determined based either on the online Microsoft Update service or WSUS if configured, or on an offline scanfile (wsusscn2.cab). This scanfile is either provided in the command line or downloaded from the Microsoft Update site. By default, the online Microsoft Update service is used (or WSUS if configured).

.PARAMETER Offline
Perform an offline scan using a scanfile.

.PARAMETER ScanFile
Specify path to the scanfile (wsusscn2.cab). Implies -Offline and -Preserve.

.PARAMETER Preserve
Preserve the scanfile.

.PARAMETER OutputFile
Specify file path to store the results in. By default, the file missing.txt in the current directory will be used.

.PARAMETER Download
Just download the scanfile (don't check for missing KBs). By default, the file will be downloaded to the current directory.

.EXAMPLE
missingkbs.ps1
Determine missing KBs using the online Microsoft Update service (or WSUS if configured)

.EXAMPLE
missingkbs.ps1 -Offline -Preserve
Determine missing KBs downloading the wsusscn2.cab scanfile and preserving it

.EXAMPLE
missingkbs.ps1 -Offline -ScanFile E:\tmp\wsusscn2.cab
Determine missing KBs using the offline wsusscn2.cab scanfile

.EXAMPLE
missingkbs.ps1 -Offline -OutputFile E:\tmp\out.txt
Determine missing KBs downloading the wsusscn2.cab scanfile saving results in out.txt

.EXAMPLE
missingkbs.ps1 -DownloadOnly E:\tmp
Download the scanfile to E:\tmp\

.LINK
https://github.com/bitsadmin/wesng/
https://blog.bitsadmin.com/windows-security-updates-for-hackers

.NOTES
On Windows, it may be required to enable this Activate.ps1 script by setting the execution policy for the user. You can do this by issuing the following PowerShell command:

PS C:\> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

For more information on Execution Policies: 
https://go.microsoft.com/fwlink/?LinkID=135170
#>

[CmdletBinding(DefaultParameterSetName = 'Online')]
param(
    [Parameter(ParameterSetName = 'Online')]
    [switch]$Online,

    [Parameter(ParameterSetName = 'Offline')]
    [switch]$Offline,

    [Parameter(ParameterSetName = 'DownloadOnly')]
    [switch]$DownloadOnly,

    [Parameter(Mandatory = $false, ParameterSetName = 'Offline')]
    [ValidateScript({
        if(-not (Test-Path $_ -PathType Leaf))
        { 
            throw 'File does not exist'
        }
        return $true
    })]
    [string]$ScanFile,

    [Parameter(Mandatory = $false, ParameterSetName = 'Offline')]
    [switch]$Preserve,

    [Parameter(Mandatory = $false, ParameterSetName = 'Online')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Offline')]
    [ValidateScript({
        $path = Split-Path $_
        if(-not (Test-Path $path -PathType Container))
        {
            throw 'Path does not exist'
        }
        return $true
    })]
    [string]$OutputFile = (Join-Path -Path (Get-Location).Path -ChildPath 'missing.txt'),

    [Parameter(ParameterSetName = 'DownloadOnly')]
    [ValidateScript({
        if(-not (Test-Path $_ -PathType Container))
        {
            throw 'Path does not exist'
        }
        return $true
    })]
    [string]$TargetPath = (Get-Location).Path
)

<#
This software is provided under the BSD 3-Clause License.
See the accompanying LICENSE file for more information.

Windows Exploit Suggester - Next Generation
Missing KBs Identifier utility - 

Author: Arris Huijgen (@bitsadmin)
Website: https://github.com/bitsadmin
#>


# Application information
$version = 1.0
$appname = "Windows Exploit Suggester: Missing KBs Identifier v$($version.ToString("0.0"))"
$url = 'https://github.com/bitsadmin/wesng/'
$banner = "$appname`n$url`n"

# Show banner
Write-Host $banner

# Online or offline scan?
# Defaults to Online
if($ScanFile)
{
    $Offline = $true
}
elseif(-not $Online)
{
    if(-not $Offline -and -not $DownloadOnly)
    {
        $Online = $true
    }
}
$specifiedScanfile = $Offline -or $ScanFile
$foundScanfile = $false

$runMode = if($Online){ 'Online' } elseif($Offline){ 'Offline' } elseif($DownloadOnly){ 'DownloadOnly' } else { 'Unknown' }
Write-Host "[I] Running in $runMode mode"

# Only check and download scanfile in case of offline scan
if ($Offline -or $DownloadOnly)
{
    # Only download the scanfile
    if ($DownloadOnly)
    {
        # Compile path for scanfile
        $scanFilePath = Join-Path -Path $TargetPath -ChildPath 'wsusscn2.cab'
    }
    # Download and perform scan
    else
    {
        # If scanfile -ScanFile parameter is not specified, check if it already exists
        # In case it doesn't exist, download it
        if ($ScanFile)
        {
            $scanFilePath = Resolve-Path $ScanFile
            $Preserve = $true
        }
        else
        {
            # Set target location to current directory or temp, depending on whether scanfile needs to be preserved
            if ($Preserve)
            {
                $targetDirectory = Get-Location
            }
            else
            {
                $targetDirectory = [System.IO.Path]::GetTempPath()
            }

            # Compile path for scanfile
            $scanFilePath = Join-Path -Path $targetDirectory -ChildPath 'wsusscn2.cab'
        }

        # Check if scanfile exists
        if (Test-Path -Path $scanFilePath -PathType Leaf)
        {
            $objScanFile = Get-Item -Path $scanFilePath
            Write-Host "[+] Using scanfile '$scanFilePath' with modification date $($objScanFile.LastWriteTime.ToShortDateString())"
            $foundScanfile = $true
        }
        elseif ($ScanFile)
        {
            Write-Host "[-] Scanfile '$scanFilePath' does not exist" -ForegroundColor Red
            exit
        }
    }

    # Only download if file doesn't exist yet
    if (-not (Test-Path -Path $scanFilePath -PathType Leaf))
    {
        Write-Host '[+] Downloading wsusscn2.cab (+/- 600MB), depending on your Internet speed this may take a while'

        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab' -OutFile $scanFilePath -UseBasicParsing
        $ProgressPreference = 'Continue'

        Write-Host "[+] Scanfile saved to '$scanFilePath'"
    }
    # Scanfile already exists
    elseif (-not $foundScanfile)
    {
        $objScanFile = Get-Item -Path $scanFilePath
        Write-Host "[+] File wsusscn2.cab already exists: '$scanFilePath'. Skipping download"
        Write-Host "[I] Scanfile modification date: $($objScanFile.LastWriteTime.ToShortDateString())"
        $foundScanfile = $true
        $Preserve = $true
        $scanFileAge = (Get-Date) - $objScanFile.LastWriteTime
        if ($scanFileAge.Days -gt 31)
        {
            Write-Host '[!] Scanfile is more than a month old, consider downloading the latest version for more accurate results' -ForegroundColor Yellow
        }
    }
}
# Display Windows Update/WSUS settings
else
{
    # UseWUServer
    $dwUseWUServer = (Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer' -ErrorAction SilentlyContinue).UseWUServer
    if(-not $dwUseWUServer)
    {
        $dwUseWUServer = 0
    }
    
    # WUServer
    if ($dwUseWUServer -eq 0)
    {
        Write-Host '[I] Windows Update online is used'
    }
    else
    {
        $strWSUS = (Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer' -ErrorAction SilentlyContinue).WUServer
        if($strWSUS)
        {
            Write-Host "[I] WSUS with URL '$strWSUS' is used"
        }
        else
        {
            Write-Host '[I] WSUS is used, but the WSUS URL could not be read' -ForegroundColor Yellow
        }
        Write-Host '    Usage of WSUS may cause the missing KB information to be incomplete'
        Write-Host '    To use Windows Update ''s online KB information, use the -Offline parameter'
    }
}

# Skip checking the current system for missing KBs if the -DownloadOnly parameter is provided
if ($DownloadOnly)
{
    Write-Host '[+] Done!'
    exit
}

# Validate whether Windows Update (wuauserv) service is not disabled
$wuauserv = Get-CimInstance -ClassName Win32_Service -Filter "Name='wuauserv'"
if ($wuauserv.StartMode -eq 'Disabled')
{
    Write-Host "[-] The 'Windows Update' service is disabled" -ForegroundColor Red
    exit
}

# Initialize Windows Update and identify missing KBs
Write-Host '[+] Identifying missing KBs...'
try
{
    $UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
}
catch
{
    Write-Host "[-] Error initializing Microsoft.Update.Session object: 0x$($Error[0].Exception.HResult.ToString("X"))" -ForegroundColor Red
    if ($Error[0].Exception.HResult -eq 0x80040154)
    {
        Write-Host '    Windows Update Client API missing. Please install the Windows Update Agent' -ForegroundColor Yellow
    }
    exit
}
$UpdateServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager'

# Only use the scanfile in case of an offline scan
if ($Offline)
{
    try
    {
        $UpdateService = $UpdateServiceManager.AddScanPackageService('Offline Sync Service', $scanFilePath, 1)
    }
    catch
    {
        Write-Host "[-] Error initializing Windows Update service: 0x$($Error[0].Exception.HResult.ToString("X"))" -ForegroundColor Red
        if ($Error[0].Exception.HResult -eq 0x80070005)
        {
            Write-Host '    Make sure to run this script as an elevated Administrator when running in Offline mode' -ForegroundColor Yellow
        }
        exit
    }
}

$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

# In case of online scan the ServerSelection and ServiceID don't need to be set
if ($Offline)
{
    $UpdateSearcher.ServerSelection = 3 # ssOthers
    $UpdateSearcher.ServiceID = $UpdateService.ServiceID
}

# Perform search for updates
try
{
    $SearchResult = $UpdateSearcher.Search('IsInstalled=0')
}
catch
{
    Write-Host "[-] Error searching for updates: 0x$($Error[0].Exception.HResult.ToString("X"))" -ForegroundColor Red
    if ($Error[0].Exception.HResult -eq 0x8024402C)
    {
        Write-Host '    Make sure your computer is connected to the Internet' -ForegroundColor Yellow
    }
    exit
}

$updateCount = $SearchResult.Updates.Count

# List updates
if ($updateCount -eq 0)
{
    if ($specifiedScanfile)
    {
        Write-Host '[+] Based on the provided scanfile no missing KBs were found'
    }
    else
    {
        if ($foundScanfile)
        {
            Write-Host '[+] Based on the scanfile no missing KBs were found'
        }
        else
        {
            Write-Host '[+] There are no missing KBs'
        }
    }
    exit
}

# Collect missing updates and show them on the screen
Write-Host '[+] List of missing KBs'
$missingUpdates = @()
for ($i = 0; $i -lt $updateCount; $i++)
{
    $update = $SearchResult.Updates.Item($i)
    for ($j = 0; $j -lt $update.KBArticleIDs.Count; $j++)
    {
        $articleId = $update.KBArticleIDs.Item($j)
        $missingUpdates += "KB$articleId"
        Write-Host "- KB$($articleId): $($update.Title)"
    }
}

# Store list of missing KBs
$missingUpdates | Out-File -FilePath $OutputFile -Encoding ASCII
if($?)
{
    Write-Host "[+] Saved list of missing updates in '$OutputFile'"
}
else
{
    Write-Host '[-] Error storing list of missing updates'
}

# Cleanup scanfile
if ($Offline)
{
    if (-not $Preserve)
    {
        Write-Host '[+] Cleaning up wsusscn2.cab'
        Remove-Item -Path $scanFilePath
    }
    else
    {
        Write-Host '[+] Skipping cleanup of the scanfile'
    }
}

Write-Host '[+] Done!'