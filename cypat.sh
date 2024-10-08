#!/bin/bash

if [ "$EUID" -ne 0 ]
then 
    echo "This script requires root permissions to run properly. Failing." >&2
    exit 1
fi

me=$(who ran sudo | awk '{print $1}')

if [ -z "$REPORT_FILE" ]
then
    REPORT_FILE="/home/${me}/report"
fi

echo "Run by: $me" > ${REPORT_FILE}

while getopts "i:u:dr:h" o; do
    case "${o}" in
        i)
            i=${OPTARG}
            
            if apt-get install ${i} -y > /dev/null
            then
                echo "Installed package ${i}" | tee -a ${REPORT_FILE}
            else
                echo "Failed to install package ${i}" | tee -a ${REPORT_FILE} >&2
            fi
            ;;
        u)
            u=${OPTARG}
            
            if apt-get remove ${u} -y > /dev/null
            then
                echo "Removed package ${i}" | tee -a ${REPORT_FILE}
            else
                echo "Failed to remove package ${i}" | tee -a ${REPORT_FILE} >&2
            fi
            ;;
        d)
            CYPAT_DEBUG=1
            echo "Debug mode enabled" | tee -a ${REPORT_FILE}
            ;;
        r)
            README=${OPTARG}
            echo "Readme file specified as ${OPTARG}" | tee -a ${REPORT_FILE}
            ;;
        h)
            echo "Usage: ${0} -r <readme> [-i <package>] [-u <package>] [-h] [-d]"
            exit
            ;;
    esac
done

if [ -z "$README" ]
then
    echo "No read me was passed to the script. Failing." >&2
    echo "Usage: ${0} -r <readme> [-i <package>] [-u <package>] [-h] [-d]"
    exit 1
fi

# Create backups
echo "Creating backups..."
cp -a /etc/pam.d/common-password /etc/pam.d/common-password.bak > /dev/null
echo "Created back up of /etc/pam.d/common-password at /etc/pam.d/common-password.bak" | tee -a ${REPORT_FILE}
cp -a /etc/ftpusers /etc/ftpusers.bak > /dev/null
echo "Created back up of /etc/ftpusers at /etc/ftpusers.bak" | tee -a ${REPORT_FILE}
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak > /dev/null
echo "Created back up of /etc/ssh/sshd_config at /etc/ssh/sshd_config.bak" | tee -a ${REPORT_FILE}
cp -a /etc/selinux/config /etc/selinux/config.bak > /dev/null
echo "Created back up of /etc/selinux/config at /etc/selinux/config.bak" | tee -a ${REPORT_FILE}
cp -a /etc/login.defs /etc/login.defs.bak > /dev/null
echo "Created back up of /etc/login.defs at /etc/login.defs.bak" | tee -a ${REPORT_FILE}
cp -a /etc/sysctl.conf /etc/sysctl.conf.bak > /dev/null
echo "Created back up of /etc/sysctl.conf at /etc/sysctl.conf.bak" | tee -a ${REPORT_FILE}

# Config PAM
echo "Configuring PAM..."

echo "Configuring common-password..."
touch /etc/security/opasswd
source /etc/os-release

apt-get install libpam-pwquality -y > /dev/null
echo "password required pam_pwquality.so" > /etc/pam.d/common-password
echo "password [success=1 default=ignore] pam_unix.so yescrypt remember=24 use_authok shadow" >> /etc/pam.d/common-password
echo "password requisite pam_deny.so" >> /etc/pam.d/common-password
echo "password required pam_permit.so" >> /etc/pam.d/common-password
echo "password optional pam_gnome_keyring.so" >> /etc/pam.d/common-password
echo "difok=8" > /etc/security/pwquality.conf
echo "minlen=12" >> /etc/security/pwquality.conf
echo "minclass=4" >> /etc/security/pwquality.conf
echo "retry=5" >> /etc/security/pwquality.conf

sed -i "s/^PASS_MIN_DAYS/PASS_MIN_DAYS 12; s/^PASS_MAX_DAYS/PASS_MAX_DAYS 90" /etc/login.defs

echo "Configured password policy with the following settings:" | tee -a ${REPORT_FILE}
echo "    yescrypt as the encryption algorithm" | tee -a ${REPORT_FILE}
echo "    5 Previous passwords are remembered" | tee -a ${REPORT_FILE}
echo "    At least 8 characters of difference between new and old passwords" | tee -a ${REPORT_FILE}
echo "    Minimum password length of 12 characters" | tee -a ${REPORT_FILE}
echo "    Password complexity of at least one character of each class required" | tee -a  ${REPORT_FILE}
echo "    Maximum of 5 retries" | tee -a ${REPORT_FILE}
echo "    Minimum of 12 days before changing password" | tee -a ${REPORT_FILE}
echo "    Maximum password age of 90 days" | tee -a ${REPORT_FILE}

echo "Configuring common-auth..."
# TODO: rest of pam

rm -f /etc/ftpusers

# ufw
echo "Installing and configuring ufw..."
apt-get install ufw -y > /dev/null
ufw disable > /dev/null
ufw default deny > /dev/null
ufw allow https > /dev/null
ufw limit OpenSSH > /dev/null
ufw enable > /dev/null

echo "ufw is configured with the following rules:" | tee -a ${REPORT_FILE}
echo "    Default action is denial" | tee -a ${REPORT_FILE}
echo "    HTTPS is allowed" | tee -a ${REPORT_FILE}
echo "    OpenSSH is limited" | tee -a ${REPORT_FILE}

echo "Manging users..."
admins=($(cat <(awk '/<pre>/,/<b>/' $README | grep -v '[^a-zA-Z0-9]' | grep -v '^$') <(echo "$me") | sort))
who_should_be=($(cat <(awk '/<pre/,/<\/pre>/' $README | grep -v '[^a-zA-Z0-9]' | grep -v '^$') <(echo "${me}") | sort))
users=($(getent passwd | awk -F: '($3>=1000)&&($3<60000){print $1}' | sort))
sudoers=($(getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | sort))

user_diff=($(diff -w <(echo "${users[*]}" | tr ' ' '\n') <(echo "${who_should_be[*]}" | tr ' ' '\n') | grep -v "[0-9]"))
admin_diff=($(diff -w <(echo "${sudoers[*]}" | tr ' ' '\n') <(echo "${admins[*]}" | tr ' ' '\n') | grep -v "[0-9]"))

if [ ! -z "$CYPAT_DEBUG" ]
then
    echo "DEBUG: Users gathered from readme:"
    printf '    %s\n' "${who_should_be[@]}"
    echo "DEBUG: Users gathered from passwd:"
    printf '    %s\n' "${users[@]}"
    echo "DEBUG: Users who should be admins according to the readme:"
    printf '    %s\n' "${admins[@]}"
    echo "DEBUG: Users who are sudoers:"
    printf '    %s\n' "${sudoers[@]}"
    echo "DEBUG: Difference between users who exist and users who should exist:"
    printf '    %s\n' "${user_diff[@]}"
    echo "DEBUG: Difference between sudoers and peolpe who should be sudoers:"
    printf '    %s\n' "${admin_diff[@]}"
    read -p "Press enter to continue" dummy
fi | tee -a ${REPORT_FILE}

# Users to add
tmp=($(echo "${user_diff[*]}" | grep ">" | awk '{print $2}'))
for user in ${tmp[*]}; do
    useradd -m $user > /dev/null
    echo "Added $user" | tee -a ${REPORT_FILE}
done

# Users to remove
tmp=($(echo "${user_diff[*]}" | grep "<" | awk '{print $2}'))
for user in ${tmp[*]}; do
    userdel $user > /dev/null
    echo "Removed $user" | tee -a ${REPORT_FILE}
done

# Users to add
tmp=($(echo "${admin_diff[*]}" | grep ">" | awk '{print $2}'))
for user in ${tmp[*]}; do
    usermod -aG sudo $user > /dev/null
    echo "Added $user to sudo" | tee -a ${REPORT_FILE}
done

# Users to remove
tmp=($(echo "${admin_diff[*]}" | grep "<" | awk '{print $2}'))
for user in ${tmp[*]}; do
    gpasswd -d $user sudo
    echo "Removed $user from sudo" | tee -a ${REPORT_FILE}
done

if ! type mkpasswd &>/dev/null
then
      apt-get install whois > /dev/null
fi

# Whoever survives the purge gets a shiny new password
users=($(getent passwd | awk -F: '($3>=1000)&&($3<60000){print $1}'))
for value in ${users[*]}; do
    chage -m 12 -M 90 -W 7 $value
      
    if [ "$value" != "$me" ]
    then
        printf "${value}:%s" `LC_ALL=C tr -dc '[:graph:]' < /dev/urandom | head -c 16`
    fi
done | chpasswd

# Malware protection
echo "Installing and running malware protection..."

echo "Handling rkhunter..."
if apt-get install rkhunter -y 
then
    echo "Installed rkhunter" | tee -a ${REPORT_FILE}
    if rkhunter --propupd > /dev/null && rkhunter -c --skip-keypress > /dev/null
    then
        echo "Successfuly ran rkhunter" | tee -a ${REPORT_FILE}
    else
        echo "rkhunter failed" | tee -a ${REPORT_FILE} >&2
    fi
else
    echo "Failed to install rkhunter" | tee -a ${REPORT_FILE} >&2
fi

echo "Configuring and running clamav..."
if apt-get install clamav clamav-daemon -y
then
    mkdir /var/log/clamav
    mkdir /root/quarantine
    chmod -R 0200 /root/quarantine
    touch /var/log/clamav/clamdscan.log

    freshclam > /dev/null

    systemctl start clamav-freshclam > /dev/null
    systemctl enable clamav-daemon > /dev/null
    systemctl start clamav-daemon > /dev/null

    sed -i -e '/^#?LogFile=/!p;$aLogFile=/var/log/clamav/clamdscan.log;/^#?LogTime=/!p;$aLogTime=yes;/^#?LogVerbose=/!p;$aLogVerbose=yes;/^#?DetectBrokenExecutables=/!p;$DetectBrokenExecutables=yes;' /etc/clamav/clamd.conf
    printf "ExcludePath ^/proc\nExcludePath ^/sys\nExcludePath ^/run\nExcludePath ^/dev\nExcludePath ^/snap\nExcludePath ^/var/lib/lxcfs/cgroup\nExcludePath ^/root/quarantine\n" >> /etc/clamav/clamd.conf 
    echo "0 0 * * * root /usr/bin/clamdscan -m --fdpass --move=/root/quarantine /" >> /etc/cron.d/clamdscan
    systemctl restart clamav-daemon > /dev/null

    echo "Installed and configured clamav with the following settings:" | tee -a ${REPORT_FILE}
    echo "    Log file is at /var/log/clamav/clamdscan.log" | tee -a ${REPORT_FILE}
    echo "    Verbose logging enabled" | tee -a ${REPORT_FILE}
    echo "    Exclude /proc /sys /run /dev /snap /var/lib/lxcfs/cgroup /root/quarantine" | tee -a ${REPORT_FILE}
    echo "    Malware dected is quarantined in /root/quarantine" | tee -a ${REPORT_FILE}
    echo "    clamdscan is run every day at midnight" | tee -a ${REPORT_FILE}

    if clamdscan -m --remove --fdpass --move=/root/quarantine / > /dev/null
    then
        echo "Ran clamdscan" | tee -a ${REPORT_FILE}
    else
        echo "Failed to run clamdscan" | tee -a ${REPORT_FILE} >&2
    fi
else
    echo "Failed to install clamav" | tee -a ${REPORT_FILE} >&2
fi

echo "Installing intrusion prevention and detection systems..."
apt-get install fail2ban -y
# TODO: configure fail2ban
apt-get install snort -y
# TODO: configure snort
apt-get install auditd -y
# TODO: configure auditd

echo "Handling common applications..."
systemctl stop nginx -y > /dev/null
systemctl disable nginx -y > /dev/null

tmp=($(echo "wireshark dwarf-fortress tor nmap ophcrack telnet telnetd crack hashcat hashcat-legacy john rainbowcrack npcap netcat cryptcat nginx aisleriot"))
for program in ${tmp[*]}; do
    apt-get purge $program -y
done | tee -a ${REPORT_FILE}

# Write new sshd_config
echo "Configuring ssh..."
wget -o /etc/ssh/sshd_config https://raw.githubusercontent.com/k4yt3x/sshd_config/master/sshd_config > /dev/null
echo "Fetched a secure sshd_config from https://raw.githubusercontent.com/k4yt3x/sshd_config/master/sshd_config" | tee -a ${REPORT_FILE}

echo "Configuring the kernel..."
wget -o /etc/sysctl.conf https://raw.githubusercontent.com/k4yt3x/sysctl/master/sysctl.conf > /dev/null
echo "Fetched a secure sshd_config from https://raw.githubusercontent.com/k4yt3x/sysctl/master/sysctl.conf" | tee -a ${REPORT_FILE}

echo "Disabling USBs..."
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
echo "usb-storage has been added to the kernel blacklist" | tee -a ${REPORT_FILE}

# TODO: mas

echo "Updating and restaring..."
apt-get update -y > /dev/null && apt-get upgrade -y
apt-get autoremove -y > /dev/null

echo "Ran apt-get and apt-get upgrade" | tee -a ${REPORT_FILE}

chown ${me}:${me} ${REPORT_FILE}
chmod 0640 ${REPORT_FILE}

read -p "About to reboot, press enter to continue..." dummy
reboot now
