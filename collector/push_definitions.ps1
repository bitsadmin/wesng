<#
Commandline:
Remove-Item ..\definitions.zip ; .\collect_msrc.ps1 ; .\collect_nvd.ps1 ; .\push_definitions.ps1
#>

# Stop if file seems corrupted
Write-Warning 'Validating definitions.zip file'
$zip = Get-ChildItem ..\definitions.zip
if($zip.Length -lt 2MB)
{
	Write-Warning 'Some issue with the definitions.zip file'
	Exit
}

# Stop if there are staged changes
$status = git status
if($status -match 'Changes to be committed')
{
	Write-Warning 'There are already pending changes, not going to automatically push updated definitions'
	Exit
}

# Stage definitions file
Write-Warning 'Staging definitions.zip...'
git add ..\definitions.zip
if(-not $?)
{
	Write-Warning 'Error staging definitions.zip file'
	Exit
}
git status

# Commit change
Write-Warning 'Committing change...'
$message = "Updated $(Get-Date -Format FileDate)"
git commit -m $message
if(-not $?)
{
	Write-Warning 'Error committing change'
	Exit
}

# Push commit
Write-Warning 'Pushing commit...'
#Read-Host 'Press enter to continue'
git push
if(-not $?)
{
	Write-Warning 'Error pushing changes'
	Exit
}