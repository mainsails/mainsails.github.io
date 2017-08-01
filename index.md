# Operating System Deployment
## Windows 10 - 1703
### Disable Cortana in OOBE
Cortana has a lovely habit of starting a conversation with you during OS deployment. Imaging a single machine in a quiet office or 100+ in a building is equally embarassing.

Rather than using depreciated settings (that happen to work just fine), modifying your unattend.xml or nasty volume hacks - I prefer to specifically target the annoyance and remove it during a capture task sequence :

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
[Set-MuteOOBECortanaVoice.ps1](https://github.com/mainsails/ps/blob/master/Imaging/Capture/Set-MuteOOBECortanaVoice.ps1)

Future deployments will carry on as normal but Cortana won't be rattling your speakers rambling on about network settings and regions.


### Remove AppX Packages
There's ongoing arguments within the OS deployment community regarding the futility of stripping out applications from our images. I've always believed in a clean, vanilla build as most do but it seems that my definition differs from some. Times have changed, the future is here and an out of the box Windows client is a different beast now.

Unless you're running LTSB, even in the Enterprise SKUs of Windows we're faced with a long list of questionable apps in a default install. We can leave it like it is, let our users decide and start documenting our responses to the imminent IG interrogations or.... Twice a year (with our shiny new build releases) we can add a line or two to our AppX removal script and stay in control :

```powershell
# List of Applications to Remove
$AppPackages  = @()
$AppPackages += 'Microsoft.3DBuilder'
$AppPackages += 'Microsoft.Appconnector'
$AppPackages += 'Microsoft.BingFinance'
$AppPackages += 'Microsoft.BingFoodAndDrink'
$AppPackages += 'Microsoft.BingHealthAndFitness'
$AppPackages += 'Microsoft.BingNews'
$AppPackages += 'Microsoft.BingSports'
$AppPackages += 'Microsoft.BingTravel'
$AppPackages += 'Microsoft.CommsPhone'
$AppPackages += 'Microsoft.ConnectivityStore'
$AppPackages += 'Microsoft.Getstarted'
$AppPackages += 'Microsoft.Messaging'
$AppPackages += 'Microsoft.Microsoft3DViewer'
$AppPackages += 'Microsoft.MicrosoftOfficeHub'
$AppPackages += 'Microsoft.MicrosoftSolitaireCollection'
$AppPackages += 'Microsoft.MinecraftUWP'
$AppPackages += 'Microsoft.Office.OneNote'
$AppPackages += 'Microsoft.Office.Sway'
$AppPackages += 'Microsoft.OneConnect'
$AppPackages += 'Microsoft.People'
$AppPackages += 'Microsoft.SkypeApp'
$AppPackages += 'microsoft.windowscommunicationsapps'
$AppPackages += 'Microsoft.WindowsFeedbackHub'
$AppPackages += 'Microsoft.WindowsPhone'
$AppPackages += 'Microsoft.WindowsReadingList'
$AppPackages += 'Microsoft.XboxApp'
$AppPackages += 'Microsoft.ZuneMusic'
$AppPackages += 'Microsoft.ZuneVideo'

# List of Core Applications to Remove (Core Applications that may not be removable)
$AppPackages += 'Microsoft.MicrosoftEdge'
$AppPackages += 'Microsoft.Windows.ParentalControls'
$AppPackages += 'Microsoft.WindowsFeedback'
$AppPackages += 'Microsoft.XboxGameCallableUI'
$AppPackages += 'Microsoft.XboxIdentityProvider'
$AppPackages += 'Windows.ContactSupport'
$AppPackages += 'Windows.PurchaseDialog'

# List of Applications to Consider Removing
#$AppPackages += 'Microsoft.BingWeather'
#$AppPackages += 'Microsoft.MicrosoftStickyNotes'
#$AppPackages += 'Microsoft.Windows.Photos'
#$AppPackages += 'Microsoft.WindowsCalculator'
#$AppPackages += 'Microsoft.WindowsCamera'
#$AppPackages += 'Microsoft.WindowsMaps'
#$AppPackages += 'Microsoft.WindowsSoundRecorder'
#$AppPackages += 'Microsoft.WindowsStore'
#$AppPackages += 'WindowsAlarms'

# Non-Microsoft Applications
$AppPackages += '2FE3CB00.PicsArt-PhotoStudio'
$AppPackages += '4DF9E0F8.Netflix'
$AppPackages += '6Wunderkinder.Wunderlist'
$AppPackages += '9E2F88E3.Twitter'
$AppPackages += 'ClearChannelRadioDigital.iHeartRadio'
$AppPackages += 'D52A8D61.FarmVille2CountryEscape'
$AppPackages += 'DB6EA5DB.CyberLinkMediaSuiteEssentials'
$AppPackages += 'Drawboard.DrawboardPDF'
$AppPackages += 'Flipboard.Flipboard'
$AppPackages += 'GAMELOFTSA.Asphalt8Airborne'
$AppPackages += 'king.com.CandyCrushSaga'
$AppPackages += 'king.com.CandyCrushSodaSaga'
$AppPackages += 'PandoraMediaInc.29680B314EFC2'
$AppPackages += 'ShazamEntertainmentLtd.Shazam'
$AppPackages += 'TheNewYorkTimes.NYTCrossword'
$AppPackages += 'TuneIn.TuneInRadio'

# Application Removal
ForEach ($App In $AppPackages) {

    $Package = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $App }
    If ($Package -ne $null) {
        Write-Host "Removing Package : $App"
        Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction SilentlyContinue
    }
    Else {
        Write-Host "Requested Package is not installed : $App"
    }

    $ProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $App }
        If ($ProvisionedPackage -ne $null) {
        Write-Host "Removing Provisioned Package : $App"
        Remove-AppxProvisionedPackage -Online -PackageName $ProvisionedPackage.PackageName -ErrorAction SilentlyContinue
    }
    Else {
        Write-Host "Requested Provisioned Package is not installed : $App"
    }

}
```
[Remove-AppXPackages.ps1](https://github.com/mainsails/ps/blob/master/Imaging/Capture/Remove-AppXPackages.ps1)

Added to our image capture task sequence, we can remove all concerning AppX packages along with the provisioned versions, preventing them from coming back every time a new user logs in. 


### BitLocker Pre-provisioning - Algorithms
Windows 10 (1511+) introduced a new BitLocker algorithm, AES-XTS. As usual, settings like this are easy to manage on domain joined machines through Group Policy/MBAM but it's worth consideration for image deployment.

BitLocker pre-provisioning during imaging is excellent, encrypting a freshly formatted disk with no data takes a split-second and keeps data secure from the very start of the process. Traditionally enabling BitLocker post-deployment can take hours on a slow disk, is an IG risk disk till it's complete, uses all disk IO bandwidth and the majority of usable space until finished.

It may be a quick-win but there's a caveat to those deploying older operating systems while running the latest ADK. Windows PE 10 will default to encypting disks with new alorithm (AES-XTS 128bit) and as it is unsupported on older operating systems, after your image has been copied to disk, the process will fail when it actually tries to boot.

The solution is simple, set the encrpytion algorithm before BitLocker pre-provisioning starts. This can be the lowest common denominator or as we'll be doing this in a Task Sequence with PowerShell, we may as well do this dynamically depending on the OS version being deployed :

```powershell
# Set Encryption Method Based on Target Operating System
If ($TSEnv.Value('TASKSEQUENCENAME') -like '*Windows 10*') {
    $EncryptionMethod = '7'
}
Else {
    $EncryptionMethod = '4'
}

# Create Registry Object
$RegistryPath    = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$RegistryEntries = @(
    @{ 'Path' = $RegistryPath ; 'Name' = 'EncryptionMethodWithXtsFdv'   ; 'Value' = $EncryptionMethod ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'EncryptionMethodWithXtsOs'    ; 'Value' = $EncryptionMethod ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'EncryptionMethodWithXtsRdv'   ; 'Value' = $EncryptionMethod ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'IdentificationField'          ; 'Value' = '1'               ; 'Type' = 'DWORD'  }
    @{ 'Path' = $RegistryPath ; 'Name' = 'IdentificationFieldString'    ; 'Value' = 'BLIFS'           ; 'Type' = 'String' }
    @{ 'Path' = $RegistryPath ; 'Name' = 'SecondaryIdentificationField' ; 'Value' = 'BLSIF'           ; 'Type' = 'String' }
)

# Create Registry Key
If (!(Test-Path -Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force
}
# Set Registry Values
ForEach ($RegistryEntry in $RegistryEntries) {
    New-ItemProperty -Path $RegistryEntry.Path -Name $RegistryEntry.Name -Value $RegistryEntry.Value -PropertyType $RegistryEntry.Type -Force
}
```
[Configure-BitLockerPreprovision.ps1](https://github.com/mainsails/ps/blob/master/Imaging/Deploy/Configure-BitLockerPreprovision.ps1)

The above is a simple boilerplate template for Windows 10 and Windows 7 deployments.
It sets the encryption method and cipher strength for :
* Fixed Data Drives
* Operating System Drives
* Removable Data Drives

* Windows 10 will have these set to AES-XTS with a key size of 256 bits
* Windows 7 will have these set to AES-CBC with a key size of 256 bits

[Microsoft Reference : Encryption algorithm and key size](https://msdn.microsoft.com/en-us/library/windows/desktop/aa376434(v=vs.85).aspx)


### Update BIOS during image deployment
I've taken a simple approach for updating machine BIOS' during imaging. I build a folder structure containing Manufacturer and Model names, drop in the executable and create a file named 'x.x.x.ver' alongside. During imaging I call a PowerShell script that recurses through this folder to match the Manufacturer/Model, reads the current BIOS version and compares it against the name of the '.ver' file. If there's no match, the executable is launched and the BIOS updated.

```
│   Update-BIOS.ps1
│
├───Dell
│   ├───Latitude 7280
│   │       1.5.2.ver
│   │       dellbiosupdate.exe
│   │
│   └───Latitude 7480
│           1.4.3.ver
│           dellbiosupdate.exe
│
└───HP
    └───EliteDesk 800
            B03.ver
            hpbiosupdate.exe
```

This allows for BIOS upgrades/downgrades as well as a seemless drag and drop replacement of new revisions by colleagues. The script can be called during the Windows PE phase but there's a caveats to watch out for. Not all of these BIOS upgrades support Windows PE and not all architectures are supported. Launching them later in a Task Sequence when Windows is running isn't as "neat" but solves this - Until all the Enterprise vendors support Windows PE on x86/x64, this is the safest option.

```powershell
Function Write-CMTraceLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [int]$ProcessID = $PID,
        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line          = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="{5}" file="">'
    $LineFormat    = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel, $ProcessID
    $Line          = $Line -f $LineFormat
    Add-Content -Value $Line -Path $Log
}

# Script Start
$TSEnv   = New-Object -COMObject Microsoft.SMS.TSEnvironment
$LogPath = $TSEnv.Value('LOGPATH')
$Log     = "$LogPath\$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName).log"

Write-CMTraceLog "BIOS Update Scan Starting"

$BIOSPassword  = 'BIOSPassword'

$BIOSStructure = Split-Path $MyInvocation.MyCommand.Path -Parent
$SystemInfo    = Get-WmiObject -Class Win32_ComputerSystem
$BIOSInfo      = Get-WmiObject -Class Win32_BIOS
$Manufacturer  = $SystemInfo.Manufacturer
$Model         = $SystemInfo.Model
$BIOSvCurrent  = $BIOSInfo.SMBIOSBIOSVersion
$BIOSSource    = Get-ChildItem -Path $BIOSStructure -Include $Model -Recurse

Write-CMTraceLog "BIOS Update Folder Structure set to $BIOSStructure"
Write-CMTraceLog "WMI Lookup on Win32_ComputerSystem : $SystemInfo"
Write-CMTraceLog "WMI Lookup on Win32_BIOS : $BIOSInfo"
Write-CMTraceLog "Manufacturer Detected as $Manufacturer"
Write-CMTraceLog "Model Detected as $Model"
Write-CMTraceLog "Current BIOS Version Detected as $BIOSvCurrent"

If ($BIOSSource) {
    Write-CMTraceLog "BIOS Update Source set to $BIOSSource"
    Write-CMTraceLog "Scanning Update Source for BIOS versions"
    $BIOSvLatest = Get-ChildItem -Path $BIOSSource -Filter '*.ver' | Select -ExpandProperty BaseName
    Write-CMTraceLog "Archived BIOS Version Detected as : $BIOSvLatest"
    If ($BIOSvCurrent -ne $BIOSvLatest) {
        Write-CMTraceLog "Machine BIOS does not match Archived BIOS"
        Write-CMTraceLog "Updating BIOS from $BIOSvCurrent to $BIOSvLatest"
        Write-CMTraceLog "Scanning Update Source for BIOS executable"
        $UpdateExe = (Get-ChildItem -Path $BIOSSource -Filter *.exe).Name
        If ($UpdateExe.Count -ne 1) {
            Write-CMTraceLog "Multiple Executables found in $BIOSSource - Exiting" -LogLevel 3
            Break
        }
        Else {
            Write-CMTraceLog "BIOS Update Executable detected as : $UpdateExe"
        }
        Copy-Item -Path $BIOSSource -Destination $env:TEMP -Recurse -Force
        Set-Location -Path $env:TEMP\$Model
        Write-CMTraceLog "New BIOS copied from $BIOSSource to $env:TEMP\$Model)"
        Write-CMTraceLog "BIOS Executable Vendor detected as : $($BIOSSource.Parent.Name)"
        If ($BIOSSource.Parent.Name -eq 'Dell') {
            $UpdateArgs = "/s /f /p=$BIOSPassword"
        }
        ElseIf ($BIOSSource.Parent.Name -eq 'HP') {
            $UpdateArgs = 'TO DO'
        }
        Else {
            Write-CMTraceLog "No Executable Arguments for $($BIOSSource.Parent.Name) are defined -LogLevel 3"
        }
        Write-CMTraceLog "Launching BIOS Update : $UpdateEXE"
        $BIOSUpdate = Start-Process -FilePath $env:TEMP\$Model\$UpdateEXE -NoNewWindow -Wait -Passthru -ArgumentList $UpdateArgs
        Write-CMTraceLog "Stopped BIOS Update : $UpdateEXE with Return Code $($BIOSUpdate.ExitCode)" -ProcessID $($BIOSUpdate.Id)
        Write-CMTraceLog "Retrieving Return Codes for $($BIOSSource.Parent.Name) Update Executable"
        If ($BIOSSource.Parent.Name -eq 'Dell') {
            Switch ($BIOSUpdate.ExitCode) {
                '0' {
                    $BIOSUpdateRtnMsg  = 'SUCCESSFUL : The update was successful'
                    $BIOSUpdateSuccess = $true      
                }
                '1' {
                    $BIOSUpdateRtnMsg = 'UNSUCCESSFUL (FAILURE) : An error occurred during the update process; the update was not successful.'
                    $BIOSUpdateSuccess = $false
                }
                '2' {
                    $BIOSUpdateRtnMsg = 'REBOOT_REQUIRED : You must restart the system to apply the updates.'
                    $BIOSUpdateSuccess = $true
                }
                '3' {
                    $BIOSUpdateRtnMsg = 'DEP_SOFT_ERROR : You attempted to update to the same version of the software. / You tried to downgrade to a previous version of the software.'
                    $BIOSUpdateSuccess = $false
                }
                '4' {
                    $BIOSUpdateRtnMsg = 'DEP_HARD_ERROR : The update was unsuccessful because the system did not meet BIOS, driver, or firmware prerequisites for the update to be applied, or because no supported device was found on the target system.'
                    $BIOSUpdateSuccess = $false
                }
                '5' {
                    $BIOSUpdateRtnMsg = 'QUAL_HARD_ERROR : The operating system is not supported by the DUP. / The system is not supported by the DUP. / The DUP is not compatible with the devices found in your system.'
                    $BIOSUpdateSuccess = $false
                }
                '6' {
                    $BIOSUpdateRtnMsg = 'REBOOTING_SYSTEM : The system is being rebooted.'
                    $BIOSUpdateSuccess = $true
                }
            }
        }
        If ($BIOSUpdateSuccess -eq $true) {
            Write-CMTraceLog "BIOS Update Returned : $BIOSUpdateRtnMsg"
            $TSEnv.Value('BIOSUpdateRestart') = $true
        }
        ElseIf ($BIOSUpdateSuccess -eq $false) {
            Write-CMTraceLog "BIOS Update Returned : $BIOSUpdateRtnMsg" -LogLevel 3
        }
        Else {
            Write-CMTraceLog "BIOS Update Returned Unknown Result" -LogLevel 2
        }
    }
    Else {
        Write-CMTraceLog "Machine BIOS matches Archived BIOS : $BIOSvCurrent"
    }
}
Else {
    Write-CMTraceLog "No Archived BIOS Version Information available for this machine" -LogLevel 2
}
If ($TSEnv.Value('BIOSUpdateRestart') -eq $true) {
    Write-CMTraceLog "Restart required"
    Write-CMTraceLog "Task Sequence Variable set to enforce restart"
}
Write-CMTraceLog "BIOS Update Scan Finished"
```
[Update-BIOS.ps1](https://github.com/mainsails/ps/blob/master/Imaging/Deploy/BIOS-Update/Update-BIOS.ps1)

This has the executable's arguments set for Dell and a placeholder for HP. I've also added a CMTrace logging function that will save the logs to the Task Sequence's LOGPATH variable (where it keeps all the other logs) and formats the output into something that will parse nicely.

After BIOS update executables are launched, they tend to exit, reboot and perform the actual firmware flash afterwards. The script takes the exit code and sets a Task Sequence Variable if a reboot is required. If an update is successully run, the Task Sequence can gracefully reboot, flash and resume!
