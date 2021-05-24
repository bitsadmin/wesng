' This software is provided under under the BSD 3-Clause License.
' See the accompanying LICENSE file for more information.
'
' Windows Exploit Suggester - Next Generation
' Missing Patches Identifier utility
'
' Author: Arris Huijgen (@bitsadmin)
' Website: https://github.com/bitsadmin

Option Explicit
On Error Resume Next

' Application information
Dim version : version   = 0.9
Dim appname : appname   = "Windows Exploit Suggester: Missing Patches Identifier v" & version
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
    StdErr.Write "    Compiles a list of missing patches on the current system." & vbCrLf
    StdErr.Write "    These missing patches are determined based either the online" & vbCrLf
    StdErr.Write "    Windows Update service or WSUS if configured, or on an offline" & vbCrLf
    StdErr.Write "    scanfile (wsusscn2.cab). This scanfile is either provided in the" & vbCrLf
    StdErr.Write "    commandline or downloaded from the Windows Update site." & vbCrLf
    StdErr.Write "    By default the online Windows Update service or WSUS if configured is used." & vbCrLf & vbCrLf
    StdErr.Write "Parameter List:" & vbCrLf
    StdErr.Write "    /F, /Offline    Perform an offline scan using a scanfile." & vbCrLf
    StdErr.Write "    /I:[filename]   Specify path to the scanfile (wsusscn2.cab). Implies /F and /P." & vbCrLf
    StdErr.Write "    /P              Preserve the scanfile." & vbCrLf
    StdErr.Write "    /O:[filename]   Specify filename to store the results in. By default the" & vbCrLf
    StdErr.Write "                    file missing.txt in the current directory will be used." & vbCrLf
    StdErr.Write "    /? or /Help     Displays this help message." & vbCrLf
    
    WScript.Quit
End If

' Check if running elevated
shell.RegRead("HKEY_USERS\s-1-5-19\")
If Err.Number <> 0 Then
    stdErr.Write "[-] This script needs to be executed as elevated Administrator" & vbCrLf
    WScript.Quit
End If

' Determine output file
Dim outputFile
If args.Exists("O") Then
    outputFile = fs.GetAbsolutePathName(args("O"))
Else
    outputFile = fs.BuildPath(shell.CurrentDirectory, "missing.txt")
End If

' Online or offline scan?
Dim offlineScan: offlineScan = args.Exists("F") Or args.Exists("Offline") Or args.Exists("I")

' Only check and download scanfile in case of offline scan
If offlineScan Then
    ' Determine scanfile
    Dim preserveFile, scanFile, objScanFile, specifiedScanfile, foundScanfile
    specifiedScanfile = args.Exists("I")
    If specifiedScanfile Then
        preserveFile = True
        scanFile = args("I")
        If fs.FileExists(scanFile) Then
            scanFile = fs.GetAbsolutePathName(scanFile)
            Set objScanFile = fs.GetFile(scanFile)
            stdOut.Write "[+] Using scanfile """ & scanFile & """ with modification date " & Split(objScanFile.DateLastModified)(0) & vbCrLf
        Else
            stdOut.Write "[-] Scanfile """ & scanFile & """ doesn't exist" & vbCrLf
            WScript.Quit
        End If

    ' If scanfile /I parameter is not specified, check if it already exists
    ' In case it doesn't exist, download it
    Else
        ' Determine if file needs to be preserved
        preserveFile = args.Exists("P")
        foundScanfile = False
        
        ' Compile path for scanfile
        scanFile = fs.BuildPath(shell.CurrentDirectory, "wsusscn2.cab")
        
        ' If /P flag is provided, save in current directory
        If Not preserveFile Then
            
            ' Check if already existing in current directory
            ' In case it does, just use that file
            If Not fs.FileExists(scanFile) Then
                
                ' By default save in %tmp% folder
                scanFile = fs.BuildPath(fs.GetSpecialFolder(2), "wsusscn2.cab") ' 2 = %tmp% folder
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
        Else
            Set objScanFile = fs.GetFile(scanFile)
            stdOut.Write "[+] File wsusscn2.cab already exists: """ & scanFile & """ with modification date " & Split(objScanFile.DateLastModified)(0) & ". Skipping download" & vbCrLf
            foundScanfile = True
            preserveFile = True
        End If
    End If

' Show Windows Update/WSUS settings
Else
    ' TODO
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
        stdOut.Write "    Usage of WSUS may cause the patch information to be incomplete. To use Windows Update's online patch information, use the /F parameter" & vbCrLf
    End If
End If    

' Initialize Windows Update and identify missing patches
stdOut.Write "[+] Identifying missing patches..." & vbCrLf
Dim UpdateSession: Set UpdateSession = CreateObject("Microsoft.Update.Session")
If Err.Number <> 0 Then
    stdOut.Write "[-] Error initializing Microsoft.Update.Session object: 0x" & Hex(Err.Number) & vbCrLf
    If Err.Number = 429 Then
        stdOut.Write "    Windows Update Client API missing. Please install the Windows Update Agent" & vbCrLf
    End If
    Err.Clear
    WScript.Quit
End If
Dim UpdateServiceManager: Set UpdateServiceManager = CreateObject("Microsoft.Update.ServiceManager")
If Err.Number <> 0 Then
    stdOut.Write "[-] Error initializing Microsoft.Update.ServiceManager object: 0x" & Hex(Err.Number) & vbCrLf
    Err.Clear
    WScript.Quit
End If

' Only use the scanfile in case of an offline scan
If offlineScan Then
    Dim UpdateService: Set UpdateService = UpdateServiceManager.AddScanPackageService("Offline Sync Service", scanFile, 1) ' 1 = usoNonVolatileService
    If Err.Number <> 0 Then
        stdOut.Write "[-] Error initializing Windows Update service: 0x" & Hex(Err.Number) & vbCrLf
        If Err.Number = 70 Then
            stdOut.Write "    Make sure to run this script as an elevated Administrator" & vbCrLf
        End If
        Err.Clear
        WScript.Quit
    End If
End If

Dim UpdateSearcher: Set UpdateSearcher = UpdateSession.CreateUpdateSearcher()

' In case of online scan the ServerSelection and ServiceID don't need to be set
If offlineScan Then
    UpdateSearcher.ServerSelection = 3 ' 3 = ssOthers
    UpdateSearcher.ServiceID = UpdateService.ServiceID
End If

Dim SearchResult: Set SearchResult = UpdateSearcher.Search("IsInstalled=0")
Dim updateCount: updateCount = searchResult.Updates.Count

' List updates
Dim Updates: Set Updates = SearchResult.Updates
If updateCount = 0 Then
    If specifiedScanfile Then
        stdOut.Write "[+] Based on the provided scanfile no missing patches were found"
    Else
        If foundScanfile Then
            stdOut.Write "[+] Based on the scanfile no missing patches were found"
        Else
            stdOut.Write "[+] There are no missing patches"
        End If
    End If
    WScript.Quit
End If

' Collect missing updates and show them on the screen
stdOut.Write "[+] List of missing patches" & vbCrLf
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
If offlineScan Then
    If Not preserveFile Then
        stdOut.Write "[+] Cleaning up wssuscan.cab" & vbCrLf
        filesys.DeleteFile scanFile
    Else
        stdOut.Write "[+] Skipping cleanup of the scanfile" & vbCrLf
    End If 
End If

stdOut.Write "[+] Done!" & vbCrLf
WScript.Quit
