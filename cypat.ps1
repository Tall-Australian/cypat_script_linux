# Password Policy
echo "Configuring Password Policy..."
Set-ADDefaultDomainPasswordPolicy -LockoutDuration 0.0:30:0.0 -LockoutThreshold 3 -MaxPasswordAge 90.0:0:0.0 -MinPasswordAge 4.0:0:0.0 -MinPasswordLength 8 -ReversibleEncryptionEnabled 0 -PasswordHistoryCount 24

# Firewall and Defender
echo "Enabling Windows Defender..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Dism /Online /Enable-Feature /FeatureName:Windows-Defender-Features
Dism /Online /Enable-Feature /FeatureName:Windows-Defender
Dism /Online /Enable-Feature /FeatureName:Windows-Defender-Gui

# Handle parameters
param (
    [String[]]$Delete,
    [String[]]$Add,
    [String[]]$Change,
    [String[]]$AddToGroup,
)

echo "Manging users..."
Remove-LocalUser -Name $Delete

foreach ($i in $Add) {
  $Tuple = $i.Split(":")
  $Password = ConvertTo-SecureString $Tuple[1]
  New-LocalUser -Name $Tuple[0] -Password $Password
}

foreach ($i in $Change) {
  $Tuple = $i.Split(":")
  $Password = ConvertTo-SecureString $Tuple[1]
  Set-LocalUser -Name $Tuple[0] -Password $Password
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
