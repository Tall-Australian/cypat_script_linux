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
$secpol = $secpol -replace "AuditSystemEvents = \d+", "AuditSystemEvents = 3"
$secpol = $secpol -replace "AuditLogonEvents = \d+", "AuditLogonEvents = 3"
$secpol = $secpol -replace "AuditObjectAccess = \d+", "AuditObjectAccess = 3"
$secpol = $secpol -replace "AuditPrivilegeUse = \d+", "AuditPrivilegeUse = 3"
$secpol = $secpol -replace "AuditPolicyChange = \d+", "AuditPolicyChange = 3"
$secpol = $secpol -replace "AuditAccountManage = \d+", "AuditAccountManage = 3"
$secpol = $secpol -replace "AuditProcessTracking = \d+", "AuditProcessTracking = 3"
$secpol = $secpol -replace "AuditDSAccess = \d+", "AuditDSAccess = 3"

# There are some other policies I'd like to change but I kinda don't know how

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
$Users_ = Get-LocalUser | ForEach-Object {$_.Name} | select-string "^[a-z]+" -CaseSensitive | where {$_.trim() -ne ""} | Sort-Object
# i strongly prefer the classic bash line of:
# sudoers=($(getent group sudo | awk -F: "{print $4}" | tr ',' '\n' ))
$Admins_ = Get-LocalGroupMember -Group "Administrators" | ForEach-Object {$_.Name.split("\")[1]} | select-string "^[a-z]+" -CaseSensitive | Sort-Object

foreach ($u in $Users_) {
    
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
