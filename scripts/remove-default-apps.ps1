#   Description:
# This script removes unwanted Apps that come with Windows. If you  do not want
# to remove certain Apps comment out the corresponding lines below.

# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
# Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

$packages = Get-AppxProvisionedPackage -Online | Select Packagename
$whitelist = @(
    "*MicrosoftEdge*", "*WindowsCalculator*", "*MSPaint*",
    "*WindowsStore*", # Cannot re-install
    "*Microsoft.VCLibs.*"
)

foreach ($app in $packages) {
    $matched = $false
    foreach ($w in $whitelist) {
        if ($app.packagename -like $w) {
            $matched = $true
            break
        }
    }

    if ($matched -eq $false) {
        write-host "Uninstalling" $app.packagename
        $tries = 0

        do {
            Get-AppxPackage -Name $app.packagename -AllUsers |
                Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online |
                where {$_.packagename -EQ $app.packagename} |
                Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction SilentlyContinue
            $tries++
        } while ((Get-AppxProvisionedPackage -Online | Select Packagename) -match $app.packagename -or $tries -ge 2)

        if ((Get-AppxProvisionedPackage -Online | Select Packagename) -match $app.packagename) {
            write-host $app.packagename "failed to uninstall after $tries tries"
        } else {
            write-host $app.packagename "successfully uninstalled after $tries tries"
        }
    }
}

# Prevents Apps from re-installing
$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1