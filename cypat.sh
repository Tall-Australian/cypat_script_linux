#!/bin/bash

# Create backups
echo "Creating backups..."
cp -a /etc/pam.d/common-password /etc/pam.d/common-password.bak
cp -a /etc/ftpusers /etc/ftpusers.bak
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cp -a /etc/selinux/config /etc/selinux/config.bak
cp -a /etc/login.defs /etc/login.defs.bak
cp -a /etc/sysctl.conf /etc/sysctl.conf.bak

# Config PAM
echo "Configuring PAM..."

echo "Configuring common-password..."
touch /etc/security/opasswd
source /etc/os-release

apt-get install libpam-pwquality -y
echo "password required pam_pwquality.so" > /etc/pam.d/common-password
echo "password [success=1 default=ignore] pam_unix.so yescrypt remember=5 use_authok shadow" >> /etc/pam.d/common-password
echo "password requisite pam_deny.so" >> /etc/pam.d/common-password
echo "password required pam_permit.so" >> /etc/pam.d/common-password
echo "password optional pam_gnome_keyring.so" >> /etc/pam.d/common-password
echo "difok=4" > /etc/security/pwquality.conf
echo "minlen=12" >> /etc/security/pwquality.conf
echo "minclass=4" >> /etc/security/pwquality.conf
echo "retry=5" >> /etc/security/pwquality.conf

sed -i "s/^PASS_MIN_DAYS/PASS_MIN_DAYS 12; s/^PASS_MAX_DAYS/PASS_MAX_DAYS 90" /etc/login.defs

echo "Configuring common-auth..."
# TODO: rest of pam

rm -f /etc/ftpusers

# ufw
echo "Installing and configuring ufw..."
apt-get install ufw -y
ufw disable
ufw default deny
ufw allow https
ufw limit ssh
ufw enable

# Arg parsing and user adding time
echo "Manging users and applications..."
while getopts "i:u" o; do
    case "${o}" in
        i)
            i=${OPTARG}
            apt-get install ${i} -y
            ;;
        u)
            u=${OPTARG}
            apt-get remove ${u} -y
            ;;
    esac
done

me=$(who ran sudo | awk '{print $1}')
admins=( $( awk '/<pre>/,/<b>/' $1 | grep -v '[^a-zA-Z0-9]' | grep -v '^$' ) )
who_should_be=($(awk '/<pre/,/</pre>/' $1 | grep -v '[^a-zA-Z0-9]' | grep -v '^$'))
users=($(getent passwd | awk -F: '($3>=1000)&&($3<60000){print $1}'))
sudoers=($(getent group sudo | awk -F: '{print $4}' | sed 's/,/\n/g'))

for user in $who_should_be; do
    useradd -m $user # If the user already exists, this does nothing. Easier than checking first.
done

# Probably not very efficient
for user in $users; do
    if [[ ! " ${who_should_be[*]} " =~ [[:space:]]${user}[[:space:]] ]]; then
        userdel $user # Delete the account; keep the files
        continue
    fi

    if [[ " ${admins} " =~ [[:space:]]${user}[[:space:]] ]]; then
        usermod -aG sudo
        continue
    elif [[ " ${sudoers} " =~ [[:space:]]${user}[[:space:]] && "${user}" != "${me}" ]]; then
        gpasswd --delete $user sudo
    fi
done

if ! type mkpasswd &>/dev/null
then
      apt-get install whois
fi

# Whoever survives the purge gets a shiny new password
for value in $users; do
      lchage -m 12 -M 90 -W 7 $value
      
      if [ "$value" != "$me" ]
      then
            mkpasswd -l 16 $value > /dev/null
      fi
done

# Malware protection
echo "Installing and running malware protection..."

echo "Handling rkhunter..."
apt-get install rkhunter -y && rkhunter --propupd && rkhunter -c --skip-keypress

echo "Configuring and running clamav..."
apt-get install clamav clamav-daemon -y
mkdir /var/log/clamav
mkdir /root/quarantine
touch /var/log/clamav/clamdscan.log
freshclam
systemctl start clamav-freshclam
systemctl enable clamav-daemon
systemctl start clamav-daemon
sed -i -e '/^#?LogFile=/!p;$aLogFile=/var/log/clamav/clamdscan.log;/^#?LogTime=/!p;$aLogTime=yes;/^#?LogVerbose=/!p;$aLogVerbose=yes;/^#?DetectBrokenExecutables=/!p;$DetectBrokenExecutables=yes;' /etc/clamav/clamd.conf
printf "ExcludePath ^/proc\nExcludePath ^/sys\nExcludePath ^/run\nExcludePath ^/dev\nExcludePath ^/snap\nExcludePath ^/var/lib/lxcfs/cgroup\nExcludePath ^/root/quarantine\n" >> /etc/clamav/clamd.conf 
echo "0 0 * * 0 root /usr/bin/clamdscan -m --fdpass --move=/root/quarantine /" >> /etc/cron.d/clamdscan
systemctl restart clamav-daemon
clamdscan -m --remove --fdpass /

echo "Installing intrusion prevention and detection systems..."
apt-get install fail2ban -y
# TODO: configure fail2ban
apt-get install snort -y
# TODO: configure snort
apt-get install auditd -y
# TODO: configure auditd

echo "Handling common applications..."
systemctl stop nginx -y
apt purge wireshark dwarf-fortress tor nmap ophcrack telnet telnetd crack hashcat hashcat-legacy john rainbowcrack npcap netcat cryptcat -y

apt autoremove -y

# Write new sshd_config
echo "Configuring ssh..."
wget -o /etc/ssh/sshd_config https://raw.githubusercontent.com/k4yt3x/sshd_config/master/sshd_config

echo "Configuring the kernel..."
wget -o /etc/sysctl.conf https://raw.githubusercontent.com/k4yt3x/sysctl/master/sysctl.conf

echo "Disabling USBs..."
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

# TODO: mas

echo "Updating and restaring..."
apt-get update -y && apt-get upgrade -y
read -p "About to reboot, press enter to continue..." dummy
reboot
