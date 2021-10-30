' This software is provided under under the BSD 3-Clause License.
' See the accompanying LICENSE file for more information.
'
' Windows Exploit Suggester - Next Generation
' Missing KBs Identifyer utility
'
' Author: Arris Huijgen (@bitsadmin)
' Website: https://github.com/bitsadmin

Option Explicit
On Error Resume Next

' Application information
Dim version : version   = 1.0
Dim appname : appname   = "Windows Exploit Suggester: Missing KBs Identifier v" & Replace(FormatNumber(version, 1), ",", ".")
Dim url     : url       = "https://github.com/bitsadmin/wesng/"
Dim banner  : banner    = appname & vbCrLf & _
                          url & vbCrLf

' Initialize
Dim fs: Set fs = CreateObject("Scripting.FileSystemObject")
Dim shell: Set shell = CreateObject("WScript.Shell")

' Collect arguments
Dim args: Set args = WScript.Arguments.Named

' Check if script is running in cscript (-1) or wscript (0)
Dim scriptHost: scriptHost = (InStrRev(UCase(WScript.FullName), "CSCRIPT") <> 0)

' Show message if running in GUI mode
If scriptHost = 0 Then
    MsgBox  banner & vbCrLf & _
            "Please run this script from the commandline using:" & vbCrLf & vbCrLf & _
            "cscript.exe " & Wscript.ScriptName, _
            vbInformation, _
            appname
    WScript.Quit
End If

' Configure outputs
Dim stdOut: Set stdOut = WScript.StdOut
Dim StdErr: Set StdErr = WScript.StdErr

' Show banner
stdOut.Write banner & vbCrLf

' Show help if requested
If args.Exists("?") or args.Exists("Help") Then
    StdErr.Write "Usage: " & Wscript.ScriptName & " [/F] [/I:[filename]] [/P] [/O:[filename]]" & vbCrLf & vbCrLf
    StdErr.Write "Description:"  & vbCrLf
    StdErr.Write "    Compiles a list of missing KBs on the current system." & vbCrLf
    StdErr.Write "    These missing KBs are determined based either the online" & vbCrLf
    StdErr.Write "    Microsoft Update service or WSUS if configured, or on an offline" & vbCrLf
    StdErr.Write "    scanfile (wsusscn2.cab). This scanfile is either provided in the" & vbCrLf
    StdErr.Write "    commandline or downloaded from the Microsoft Update site." & vbCrLf
    StdErr.Write "    By default the online Microsoft Update service is used (or WSUS if configured)." & vbCrLf & vbCrLf
    StdErr.Write "Parameter List:" & vbCrLf
    StdErr.Write "    /F or /Offline  Perform an offline scan using a scanfile." & vbCrLf
    StdErr.Write "    /I:[filename]   Specify path to the scanfile (wsusscn2.cab). Implies /F and /P." & vbCrLf
    StdErr.Write "    /P              Preserve the scanfile." & vbCrLf
    StdErr.Write "    /O:[filename]   Specify filename to store the results in. By default the" & vbCrLf
    StdErr.Write "                    file missing.txt in the current directory will be used." & vbCrLf
    StdErr.Write "    /D:[directory]  Just download the scanfile (don't check for missing KBs)." & vbCrLf
    StdErr.Write "                    By default the file will be downloaded to the current directory." & vbCrLf
    StdErr.Write "    /? or /Help     Displays this help message." & vbCrLf & vbCrLf
    StdErr.Write "Examples:" & vbCrLf
    StdErr.Write "    Determine missing KBs using online Microsoft Update service (or WSUS if configured)" & vbCrLf
    StdErr.Write "    cscript.exe " & Wscript.ScriptName & vbCrLf & vbCrLf
    StdErr.Write "    Determine missing KBs downloading the wsusscn2.cab scanfile and preserving it" & vbCrLf
    StdErr.Write "    cscript.exe " & Wscript.ScriptName & " /F /P" & vbCrLf & vbCrLf
    StdErr.Write "    Determine missing KBs using the offline wsusscn2.cab scanfile" & vbCrLf
    StdErr.Write "    cscript.exe " & Wscript.ScriptName & " /F /I:E:\tmp\wsusscn2.cab" & vbCrLf & vbCrLf
    StdErr.Write "    Determine missing KBs downloading the wsusscn2.cab scanfile saving results in out.txt" & vbCrLf
    StdErr.Write "    cscript.exe " & Wscript.ScriptName & " /F /O:E:\tmp\out.txt" & vbCrLf & vbCrLf
    StdErr.Write "    Download the scanfile to E:\tmp\" & vbCrLf
    StdErr.Write "    cscript.exe " & Wscript.ScriptName & " /D:E:\tmp" & vbCrLf & vbCrLf
    
    WScript.Quit
End If

' Check if running elevated
' Only when just downloading the scanfile, no elevation is required
Dim justDownload: justDownload = args.Exists("D")
If not justDownload Then
    shell.RegRead("HKEY_USERS\s-1-5-19\")
    If Err.Number <> 0 Then
        stdErr.Write "[-] This script needs to be executed as an elevated Administrator" & vbCrLf
        WScript.Quit
    End If
End If

' Determine output file
Dim outputFile
If args.Exists("O") Then
    outputFile = fs.GetAbsolutePathName(args("O"))
Else
    outputFile = fs.BuildPath(shell.CurrentDirectory, "missing.txt")
End If

' Online or offline scan?
Dim offlineMode: offlineMode = args.Exists("F") Or args.Exists("Offline") Or args.Exists("I") Or args.Exists("D")
Dim specifiedScanfile, foundScanfile, scanFile

' Only check and download scanfile in case of offline scan
If offlineMode Then
    ' Determine scanfile
    Dim preserveFile, objScanFile, scanFileAge, targetDirectory
    targetDirectory = shell.CurrentDirectory
    
    ' Only download the scanfile
    If justDownload Then
        ' Determine destination directory for download
        targetDirectory = args("D")
        If Len(targetDirectory) = 0 Then
            targetDirectory = shell.CurrentDirectory
        End If
        
        If Not fs.FolderExists(targetDirectory) Then
            stdErr.Write "[-] Output directory """ & targetDirectory & """ does not exist" & vbCrLf
            WScript.Quit
        End If
        
        ' Compile path for scanfile
        scanFile = fs.BuildPath(targetDirectory, "wsusscn2.cab")
    
    ' Download and perform scan
    Else
        ' If scanfile /I parameter is not specified, check if it already exists
        ' In case it doesn't exist, download it
        specifiedScanfile = args.Exists("I")
        preserveFile = args.Exists("P")
        If specifiedScanfile Then
            preserveFile = True
            scanFile = args("I")
        Else
            ' Determine if file needs to be preserved
            If preserveFile Then
                targetDirectory = shell.CurrentDirectory
            Else
                targetDirectory = fs.GetSpecialFolder(2) ' 2 = %tmp% folder
            End If
            
            ' Compile path for scanfile
            scanFile = fs.BuildPath(targetDirectory, "wsusscn2.cab")
        End If
        
        ' Check if scanfile exists
        If fs.FileExists(scanFile) Then
            scanFile = fs.GetAbsolutePathName(scanFile)
            Set objScanFile = fs.GetFile(scanFile)
            stdOut.Write "[+] Using scanfile """ & scanFile & """ with modification date " & Split(objScanFile.DateLastModified)(0) & vbCrLf
            foundScanfile = True
        ElseIf specifiedScanfile Then
            stdErr.Write "[-] Scanfile """ & scanFile & """ does not exist" & vbCrLf
            WScript.Quit
        End If
    End If

    ' Only download if file doesn't exist yet
    If Not fs.FileExists(scanFile) Then
        stdOut.Write "[+] Downloading wsusscn2.cab (+/- 1GB), depending on your Internet speed this may take a while" & vbCrLf

        ' Initialize HTTP object
        Dim stream
        Dim http: Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
        If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest")
        If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP")
        If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP")

        ' Send request and store file
        http.Open "GET", "http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab", False
        http.Send
        Set stream = CreateObject("Adodb.Stream")
        With stream
            .Type = 1                   ' 1 = adTypeBinary
            .Open
            .Write http.ResponseBody
            .SaveToFile scanFile, 2     ' 2 = adSaveCreateOverWrite
        End With
        stdOut.Write "[+] Download saved to """ & scanFile & """" & vbCrLf
    
    ' Scanfile already exists
    ElseIf Not foundScanfile Then
        Set objScanFile = fs.GetFile(scanFile)
        stdOut.Write "[+] File wsusscn2.cab already exists: """ & scanFile & """. Skipping download" & vbCrLf
        stdOut.Write "[I] Scanfile modification date: " & Split(objScanFile.DateLastModified)(0) & vbCrLf
        foundScanfile = True
        preserveFile = True
        scanFileAge = DateDiff("d", objScanFile.DateLastModified, Now())
        If scanFileAge > 31 Then
            stdOut.Write "[!] Scanfile is more than a month old, consider downloading the latest version for more accurate results" & vbCrLf
        End If
    End If

' Show Windows Update/WSUS settings
Else
    Dim dwUseWUServer: dwUseWUServer = shell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\UseWUServer")
    If err.number <> 0 Or dwUseWUServer = 0 Then
        stdOut.Write "[I] Windows Update online is used" & vbCrLf
        Err.Clear
    Else
        Dim strWSUS: strWSUS = shell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\WUServer")
        If err.number <> 0 Then
            stdOut.Write "[I] WSUS is used, but the WSUS URL could not be read" & vbCrLf
            Err.Clear
        Else
            stdOut.Write "[I] WSUS with URL """ & strWSUS & """ is used" & vbCrLf
        End if
        stdOut.Write "    Usage of WSUS may cause the missing KB information to be incomplete" & vbCrLf
        stdOut.Write "    To use Windows Update's online KB information, use the /F parameter" & vbCrLf
    End If
End If

' Skip checking the current system for missing KBs if the /D parameter is provided
If justDownload Then
    stdOut.Write "[+] Done!" & vbCrLf
    WScript.Quit
End If

' Validate whether Windows Update (wuauserv) service is not disabled
Dim wmi: Set wmi = GetObject("winmgmts://./ROOT/CIMv2")
Dim wuauserv: Set wuauserv = wmi.Get("Win32_Service.Name='wuauserv'")
If wuauserv.StartMode = "Disabled" Then
    stdErr.Write "[-] The ""Windows Update"" service is disabled" & vbCrLf
    WScript.Quit
End If

' Initialize Windows Update and identify missing KBs
stdOut.Write "[+] Identifying missing KBs..." & vbCrLf
Dim UpdateSession: Set UpdateSession = CreateObject("Microsoft.Update.Session")
If Err.Number <> 0 Then
    stdErr.Write "[-] Error initializing Microsoft.Update.Session object: 0x" & Hex(Err.Number) & vbCrLf
    If Err.Number = 429 Then
        stdOut.Write "    Windows Update Client API missing. Please install the Windows Update Agent" & vbCrLf
    End If
    WScript.Quit
End If
Dim UpdateServiceManager: Set UpdateServiceManager = CreateObject("Microsoft.Update.ServiceManager")
If Err.Number <> 0 Then
    stdErr.Write "[-] Error initializing Microsoft.Update.ServiceManager object: 0x" & Hex(Err.Number) & vbCrLf
    WScript.Quit
End If

' Only use the scanfile in case of an offline scan
If offlineMode Then
    Dim UpdateService: Set UpdateService = UpdateServiceManager.AddScanPackageService("Offline Sync Service", scanFile, 1) ' 1 = usoNonVolatileService
    If Err.Number <> 0 Then
        stdErr.Write "[-] Error initializing Windows Update service: 0x" & Hex(Err.Number) & vbCrLf
        If Err.Number = 70 Then
            stdOut.Write "    Make sure to run this script as an elevated Administrator" & vbCrLf
        End If
        WScript.Quit
    End If
End If

Dim UpdateSearcher: Set UpdateSearcher = UpdateSession.CreateUpdateSearcher()

' In case of online scan the ServerSelection and ServiceID don't need to be set
If offlineMode Then
    UpdateSearcher.ServerSelection = 3 ' 3 = ssOthers
    UpdateSearcher.ServiceID = UpdateService.ServiceID
End If

Dim SearchResult: Set SearchResult = UpdateSearcher.Search("IsInstalled=0")
Dim updateCount: updateCount = searchResult.Updates.Count

' List updates
Dim Updates: Set Updates = SearchResult.Updates
If updateCount = 0 Then
    If specifiedScanfile Then
        stdOut.Write "[+] Based on the provided scanfile no missing KBs were found"
    Else
        If foundScanfile Then
            stdOut.Write "[+] Based on the scanfile no missing KBs were found"
        Else
            stdOut.Write "[+] There are no missing KBs"
        End If
    End If
    WScript.Quit
End If

' Collect missing updates and show them on the screen
stdOut.Write "[+] List of missing KBs" & vbCrLf
Dim i, j, u, update, articleId
Dim missingUpdates(): Redim missingUpdates(updateCount)
u = 0
For i = 0 to updateCount-1
    Set update = searchResult.Updates.Item(i)
    For j = 0 to update.KBArticleIDs.Count-1
        ' Expand array if needed
        If u > UBound(missingUpdates) Then
            ReDim Preserve missingUpdates(UBound(missingUpdates) + 1)
        End If
        
        ' Store KB in array
        articleId = update.KBArticleIDs.Item(j)
        missingUpdates(u) = "KB" & articleId
        
        ' Output to console
        stdOut.Write "- KB" & articleId & ": " & update.Title & vbCrLf
        
        ' Increase index
        u = u + 1
    Next
Next

' Store list of missing KBs
Dim missingFile: Set missingFile = fs.CreateTextFile(outputFile, True)
missingFile.Write Join(missingUpdates, vbCrLf)
missingFile.Close2
stdOut.Write "[+] Saved list of missing updates in """ & outputFile & """" & vbCrLf

' Cleanup scanfile
If offlineMode Then
    If Not preserveFile Then
        stdOut.Write "[+] Cleaning up wssuscan.cab" & vbCrLf
        fs.DeleteFile scanFile
    Else
        stdOut.Write "[+] Skipping cleanup of the scanfile" & vbCrLf
    End If 
End If

stdOut.Write "[+] Done!" & vbCrLf
WScript.Quit
