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
