# Include below line (With comment) to require adminsitrator priveleges
#Requires -RunAsAdministrator

# Password Policy
echo "Configuring Password Policy..."

# Export and load secpol.msc
$secpolTempFile = "C:\secpol.cfg"
secedit /export /cfg /$secpolTempFile
$secpol = Get-Content $secpolTempFile

# Change policies
$secpol = $secpol -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 12"
$secpol = $secpol -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = 90"
$secpol = $secpol -replace "PasswordComplexity = \d+", "PasswordComplexity = 1"
$secpol = $secpol -replace "LockoutBadCount = \d+", "LockoutBadCount = 5"
$secpol = $secpol -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24"
$secpol = $secpol -replace "ClearTextPassword = \d+", "ClearTextPassword = 1"

# Sets all audit policies to log both successes and failures (Simplifies code)
auditpol /set /category:* /success:enable /failure:enable

# There are some other policies I'd like to change but I kinda don't know how

# Set Minimum Password Length Audit to 14 (Not entirely sure what this does but it gets me points: I think it logs when applications accept passwords shorter than 12 characters?)
Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Name "MinimumPasswordLengthAudit" -value "12"

# Sets account lockout policy configures in lockout.inf
secedit /configure /db c:\windows\security\local.sdb /cfg "$PSScriptRoot\lockout.inf" /areas SECURITYPOLICY

# Some more policies: Thanks to https://github.com/Adamapb/WIndows_Stuff/
 # Disable Autologin of Admins
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
# Don't display last user
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
# Enable UAC on high
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
# Enable CTRL+ALT+DEL
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
# Disable machine account password changes
reg add HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f

# Enable automatic updates (As much as can be done on windows jiprgjeijojnhegor I hate windows)
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

# Clean up
$secpol | Set-Content $secpolTempFile
secedit /configure /db %windir%\security\local.sdb /cfg $secpolTempFile /areas SECURITYPOLICY | Out-Null
rm $secpolTempFile

# Firewall and Defender
echo "Enabling Windows Defender..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Dism /Online /Enable-Feature /FeatureName:Windows-Defender-Features
Dism /Online /Enable-Feature /FeatureName:Windows-Defender
Dism /Online /Enable-Feature /FeatureName:Windows-Defender-Gui
# Enable Windows Defender registry keys that may have been changed
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

# Handle parameters
param (
    [String[]]$CreateGroup,
    [String[]]$AddToGroup,
    [Parameter(Mandatory=$true)]
    [String]$Readme,
)

echo "Manging users..."
$ReadmeText = Get-Content -Path $Readme
$UsersInReadme = New-Object System.Collections.Generic.List[System.Object]
$AdminsInReadme = New-Object System.Collections.Generic.List[System.Object]
$idx = 1

# Extract users
# this is so much easier on linux iswtg
while($ReadmeText[$idx-1] -notmatch '<pre>') { $idx++ }
while($ReadmeText[$idx] -notmatch '<b>') {
    if($ReadmeText[$idx] -match '^[a-z]+') {
        $AdminsInReadme.Add($ReadmeText[$idx].split(' ')[0])
    }
    $idx++
}
$idx++
while($ReadmeText[$idx] -notmatch '</pre>') {
    if($ReadmeText[$idx] -match '^[a-z]+') {
        $AdminsInReadme.Add($ReadmeText[$idx].split(' ')[0])
    }
    $idx++
}

$UserInReadme = $UserInReadme | Sort-Object
$AdminInReadme = $AdminInReadme | Sort-Object
#i cannot emphasize how much easier this is on linux like
# user=($(getent passwd | awk -F: "($3>=1000&&$3<60000){print $1}"))
$Users_ = Get-LocalUser | ForEach-Object {$_.Name} | select-string "^[a-z]+" -CaseSensitive | Sort-Object
$Users = New-Object System.Collections.Generic.List[System.Object]
# i strongly prefer the classic bash line of:
# sudoers=($(getent group sudo | awk -F: "{print $4}" | tr ',' '\n' ))
$Admins_ = Get-LocalGroupMember -Group "Administrators" | ForEach-Object {$_.Name.split("\")[1]} | select-string "^[a-z]+" -CaseSensitive | Sort-Object
$Admins = New-Object System.Collections.Generic.List[System.Object]

foreach ($u in $Users_) {
    $Users.Add($u.ToString().trim())
}
foreach ($a in $Admins_) {
    $Admins.Add($a.ToString().trim())
}

foreach ($i in $CreateGroup) {
    New-LocalGroup -Name $i
}

foreach ($i in $AddToGroup) {
  $Tuple = $i.Split(":")
  Add-LocalGroupMember -Group $Tuple[0] -Member $Tuple[1]
}

# Update
echo "Updating and restaring..."
Install-Module -Name PSWindowsUpdate -Force
Read-Host -Prompt "About to reboot, press enter to continue..." | Out-Null
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
