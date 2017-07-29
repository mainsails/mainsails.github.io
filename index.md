# Operating System Deployment
## Windows 10 - 1703
### Disable Cortana in OOBE
Cortana has a lovely habit of wanting a conversation with you during OS deployment. Imaging a single machine in a quiet office or 100+ in a building is equally embarassing.

Rather than using depreciated settings (that work just fine) and/or modifying your unattend.xml, I prefer to specifically target the annoyance and remove it during a capture task sequence :

```powershell
$Key   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE'
$Name  = 'DisableVoice'
$Value = '1'
$Type  = 'DWORD'

# Create registry key if it doesn't exist
If (-not (Test-Path -LiteralPath $Key -ErrorAction 'Stop')) {
    Try {
        $null = New-Item -Path $Key -ItemType 'Registry' -Force -ErrorAction 'Stop'
    }
    Catch {
        Throw
    }
}

# Set registry value if it doesn't exist
If (-not (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction 'SilentlyContinue')) {
    $null = New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -ErrorAction 'Stop'
}
# Update registry value if it does exist
Else {
    $null = Set-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -ErrorAction 'Stop'
}
```
https://github.com/mainsails/ps/blob/master/Imaging/Capture/Set-MuteOOBECortanaVoice.ps1






Here is some code :
1. Get files
```powershell
$dir = Get-ChildItem -Path $env:ALLUSERSPROFILE
```
2. List files
```powershell
$dir
```

### Header 3
Here's another bit of text

Here is another code snippet
```powershell
$dir = Get-ChildItem -Path $env:ALLUSERSPROFILE
$dir
```
