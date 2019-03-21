' ------------------------
' WES-NG validation script
' For https://github.com/bitsadmin/wesng
' Execute this script via the commandline using: cscript listupdates.vbs > updates_yyyyMMdd.txt
' ------------------------

Set updateSession = CreateObject("Microsoft.Update.Session")
updateSession.ClientApplicationID = "WES-NG validation script"

Set updateSearcher = updateSession.CreateUpdateSearcher()
Set searchResult = updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

Dim line, kb
For i = 0 To searchResult.Updates.Count-1
    line = ""
    Set update = searchResult.Updates.Item(i)
    For j = 0 To update.KBArticleIDs.Count-1
        kb = update.KBArticleIDs.Item(j)
        line = line & "KB" & CStr(kb)
        If j < update.KBArticleIDs.Count-1 Then
            line = line & ", "
        End If
    Next
    
    WScript.Echo line & ": " & update.Title
Next

If searchResult.Updates.Count = 0 Then
    WScript.Echo "There are no applicable updates."
End If

' Source: https://docs.microsoft.com/en-us/windows/desktop/wua_sdk/searching--downloading--and-installing-updates