#!/bin/bash

invoc_date=$(date "+%Y-%m-%d")
# Assign invoc_time to current time
invoc_time=$(date "+%T")
# Replace : with _ to avoid naming errors
invoc_time=${invoc_time//:/_}

function log {
    while read line; do
        printf "%s: %s\n" "$(date -Isec)" "$line"
    done | tee -a "$1"
}

if [ "$EUID" -ne 0 ]
then 
    echo "This script requires root permissions to run properly. Failing." >&2
    exit 1
fi

source /etc/os-release

me=$(who ran sudo | awk '{print $1}')

if [ -z "$STDERR" ]
then
    STDERR="/dev/stderr"
fi

if [ -z "$REPORT_FILE" ]
then
    REPORT_FILE="/var/log/cypat-${ID}-${invoc_time}.log"
fi

if [ -z "$ERR_REPORT_FILE" ]
then
    ERR_REPORT_FILE="/var/log/cypat-${ID}-${invoc_time}.err.log"
fi

# Redirects all errors to $ERR_REPORT_FILE, unless told explicitly not to.
if [ -n "$NO_REDIRECT_ERR" ] 
then
    exec 2> >(log "$ERR_REPORT_FILE" > "$STDERR")
fi

echo "Run by: $me" | log "${REPORT_FILE}"
echo "Run on: $PRETTY_NAME" | log "${REPORT_FILE}"

if apt-get update -y > /dev/null
then
    echo "Updated apt sources" | log "${REPORT_FILE}"
else
    echo "Failed to update apt sources" >&2
fi

while getopts "i:u:dDhr:R:E:" o; do
    case "${o}" in
        i)
            i=${OPTARG}
            
            if apt-get install ${i} -y > /dev/null
            then
                echo "Installed package ${i}" | log "${REPORT_FILE}"
            else
                echo "Failed to install package ${i}" | log "${REPORT_FILE}" >&2
            fi
            ;;
        u)
            u=${OPTARG}
            
            if apt-get remove ${u} -y > /dev/null
            then
                echo "Removed package ${i}" | log "${REPORT_FILE}"
            else
                echo "Failed to remove package ${i}" | log "${REPORT_FILE}" >&2
            fi
            ;;
        d)
            CYPAT_DEBUG=1
            echo "Debug mode enabled" | log "${REPORT_FILE}"
            ;;
        D)
            USE_USERDEL=1
            echo "User deletion mode enabled" | log "${REPORT_FILE}"
            ;;
        r)
            README=${OPTARG}
            echo "Readme file specified as ${OPTARG}" | log "${REPORT_FILE}"
            ;;
        R)
            olog=${REPORT_FILE}
            REPORT_FILE=${OPTARG}
            mv $olog $REPORT_FILE > /dev/null
            echo "Report file specified as ${OPTARG}" | log "$OPTARG"
            ;;
        E)
            olog=${ERR_REPORT_FILE}
            ERR_REPORT_FILE=${OPTARG}
            mv $olog $ERR_REPORT_FILE > /dev/null
            echo "Error log file specified as ${OPTARG}" | log "$OPTARG"
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
if mv -f /etc/pam.d/common-password /etc/pam.d/common-password.bak > /dev/null 
then
    echo "Created back up of /etc/pam.d/common-password at /etc/pam.d/common-password.bak" | log "${REPORT_FILE}"
fi

if mv -f /etc/ftpusers /etc/ftpusers.bak > /dev/null 
then
    echo "Created back up of /etc/ftpusers at /etc/ftpusers.bak" | log "${REPORT_FILE}"
fi

if mv -f /etc/ssh/sshd_config /etc/ssh/sshd_config.bak > /dev/null 
then
    echo "Created back up of /etc/ssh/sshd_config at /etc/ssh/sshd_config.bak" | log "${REPORT_FILE}"
fi

if mv -f /etc/selinux/config /etc/selinux/config.bak > /dev/null 
then
    echo "Created back up of /etc/selinux/config at /etc/selinux/config.bak" | log "${REPORT_FILE}"
fi

if mv -f /etc/login.defs /etc/login.defs.bak > /dev/null 
then
    echo "Created back up of /etc/login.defs at /etc/login.defs.bak" | log "${REPORT_FILE}"
fi

if mv -f /etc/sysctl.conf /etc/sysctl.conf.bak > /dev/null 
then
    echo "Created back up of /etc/sysctl.conf at /etc/sysctl.conf.bak" | log "${REPORT_FILE}"
fi

# Config PAM
echo "Configuring PAM..."

echo "Configuring common-password..."
touch /etc/security/opasswd

apt-get install libpam-pwquality -y > /dev/null
echo "password required pam_pwquality.so" > /etc/pam.d/common-password
echo "password [success=1 default=ignore] pam_unix.so yescrypt remember=24 use_authok shadow" >> /etc/pam.d/common-password
echo "password requisite pam_deny.so" >> /etc/pam.d/common-password
echo "password required pam_permit.so" >> /etc/pam.d/common-password

# If gnome is running, use the keyring.
if (set -eou pipefail; ps aux | grep -v "grep" | grep "gnome" > /dev/null) 
then
    echo "password optional pam_gnome_keyring.so" >> /etc/pam.d/common-password
fi

echo "difok=8" > /etc/security/pwquality.conf
echo "minlen=12" >> /etc/security/pwquality.conf
echo "minclass=4" >> /etc/security/pwquality.conf
echo "retry=5" >> /etc/security/pwquality.conf

sed -i "s/^PASS_MIN_DAYS/PASS_MIN_DAYS 12; s/^PASS_MAX_DAYS/PASS_MAX_DAYS 90" /etc/login.defs

echo "Configured password policy with the following settings:" | log "${REPORT_FILE}"
echo "    yescrypt as the encryption algorithm" | log "${REPORT_FILE}"
echo "    5 Previous passwords are remembered" | log "${REPORT_FILE}"
echo "    At least 8 characters of difference between new and old passwords" | log "${REPORT_FILE}"
echo "    Minimum password length of 12 characters" | log "${REPORT_FILE}"
echo "    Password complexity of at least one character of each class required" | log "${REPORT_FILE}"
echo "    Maximum of 5 retries" | log "${REPORT_FILE}"
echo "    Minimum of 12 days before changing password" | log "${REPORT_FILE}"
echo "    Maximum password age of 90 days" | log "${REPORT_FILE}"

echo "Configuring common-auth..."

# Unset nullok
# this shouldn't be necessary due to the new password policy, but cypat still checks for this
sed 's/nullok//g' -i /etc/pam.d/common-auth

rm -f /etc/ftpusers

# ufw
echo "Installing and configuring ufw..."
apt-get install ufw -y > /dev/null
ufw disable > /dev/null
ufw default deny > /dev/null
ufw allow https > /dev/null
ufw limit OpenSSH > /dev/null
ufw enable > /dev/null

echo "ufw is configured with the following rules:" | log "${REPORT_FILE}"
echo "    Default action is denial" | log "${REPORT_FILE}"
echo "    HTTPS is allowed" | log "${REPORT_FILE}"
echo "    OpenSSH is limited" | log "${REPORT_FILE}"

echo "Manging users..."
admins=($(cat <(awk '/<pre>/,/<b>/' $README | grep -v '[^a-zA-Z0-9]' | grep -v '^$') <(echo "$me")))
who_should_be=($(cat <(awk '/<pre/,/<\/pre>/' $README | grep -v '[^a-zA-Z0-9]' | grep -v '^$') <(echo "${me}")))
users=($(getent passwd | awk -F: '($3>=1000)&&($3<60000){print $1}'))
sudoers=($(getent group sudo | awk -F: '{print $4}' | tr ',' '\n'))

if [ ! -z "$CYPAT_DEBUG" ]
then
    echo "DEBUG: Users gathered from readme:"
    printf '    %s\n' "${who_should_be[@]}"
    echo "DEBUG: Users gathered from passwd:"
    printf '    %s\n' "${users[@]}"
    echo "DEBUG: Users who should be admins according to the readme:"
    printf '    %s\n' "${admins[@]}"
    echo "DEBUG: Users who are sudoers:"
    read -p "Press enter to continue" dummy
fi | log "${REPORT_FILE}"

# Users to add.
while read user 
do
    useradd -m $user
    echo "Added user: $user" | log "${REPORT_FILE}"
done < <(comm -23 <(printf "%s\n" "${who_should_be[@]}" | sort) <(printf "%s\n" "${users[@]}" | sort))

# Users to delete.
while read user 
do
    # Userdel or passwd -l + chage -E 0 + usermod -s /sbin/nologin
    if [ -z "$USE_USERDEL" ]
    then
        passwd -l $user
        chage -E 0 $user
        usermod -s /sbin/nologin $user
    else
        userdel $user
    fi
    
    echo "Deleted user: $user" | log "${REPORT_FILE}"
done < <(comm -13 <(printf "%s\n" "${who_should_be[@]}" | sort) <(printf "%s\n" "${users[@]}" | sort))

# Users to add.
while read user 
do
    usermod -aG sudo $user
    echo "Added $user to sudo" | log "${REPORT_FILE}"
done < <(comm -23 <(printf "%s\n" "${admins[@]}" | sort) <(printf "%s\n" "${sudoers[@]}" | sort))

# Users to delete.
while read user 
do
    gpasswd -d $user sudo
    echo "Removed $user to sudo" | log "${REPORT_FILE}"
done < <(comm -13 <(printf "%s\n" "${admins[@]}" | sort) <(printf "%s\n" "${sudoers[@]}" | sort))

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
        printf "${value}:%s" $(LC_ALL=C tr -dc '[:graph:]' < /dev/urandom | head -c 16)
    fi
done | chpasswd

# Malware protection
echo "Installing and running malware protection..."

echo "Handling rkhunter..."
if apt-get install rkhunter -y 
then
    echo "Installed rkhunter" | log "${REPORT_FILE}"
    if rkhunter --propupd > /dev/null && rkhunter -c --skip-keypress > /dev/null
    then
        echo "Successfuly ran rkhunter" | log "${REPORT_FILE}"
    else
        echo "rkhunter failed" | log "${REPORT_FILE}" >&2
    fi
else
    echo "Failed to install rkhunter" | log "${REPORT_FILE}" >&2
fi

echo "Configuring and running clamav..."
if apt-get install clamav clamav-daemon -y
then
    mkdir /var/log/clamav
    mkdir /root/quarantine
    chmod -R 0200 /root/quarantine # Read only
    touch /var/log/clamav/clamdscan.log

    freshclam > /dev/null # I have genuinely never seen freshclam work.

    systemctl start clamav-freshclam > /dev/null
    systemctl enable clamav-daemon > /dev/null
    systemctl start clamav-daemon > /dev/null

    sed -i -e '/^#?LogFile=/!p;$aLogFile=/var/log/clamav/clamdscan.log;/^#?LogTime=/!p;$aLogTime=yes;/^#?LogVerbose=/!p;$aLogVerbose=yes;/^#?DetectBrokenExecutables=/!p;$DetectBrokenExecutables=yes;' /etc/clamav/clamd.conf
    printf "ExcludePath ^/proc\nExcludePath ^/sys\nExcludePath ^/run\nExcludePath ^/dev\nExcludePath ^/snap\nExcludePath ^/var/lib/lxcfs/cgroup\nExcludePath ^/root/quarantine\n" >> /etc/clamav/clamd.conf 
    echo "0 0 * * * root /usr/bin/clamdscan -m --fdpass --move=/root/quarantine /" >> /etc/cron.d/clamdscan
    systemctl restart clamav-daemon > /dev/null

    echo "Installed and configured clamav with the following settings:" | log "${REPORT_FILE}"
    echo "    Log file is at /var/log/clamav/clamdscan.log" | log "${REPORT_FILE}"
    echo "    Verbose logging enabled" | log "${REPORT_FILE}"
    echo "    Exclude /proc /sys /run /dev /snap /var/lib/lxcfs/cgroup /root/quarantine" | log "${REPORT_FILE}"
    echo "    Malware dected is quarantined in /root/quarantine" | log "${REPORT_FILE}"
    echo "    clamdscan is run every day at midnight" | log "${REPORT_FILE}"

    if clamdscan -m --remove --fdpass --move=/root/quarantine / > /dev/null
    then
        echo "Ran clamdscan" | log "${REPORT_FILE}"
    else
        echo "Failed to run clamdscan" >&2
    fi
else
    echo "Failed to install clamav" >&2
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

tmp=($(echo "wireshark dwarf-fortress tor nmap ophcrack telnet telnetd crack hashcat hashcat-legacy john rainbowcrack npcap netcat cryptcat nginx aisleriot deluge"))
for program in ${tmp[*]}; do
    apt-get purge $program -y
done | log "${REPORT_FILE}"

# Write new sshd_config
echo "Configuring ssh..."
wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/k4yt3x/sshd_config/master/sshd_config
echo "Fetched a secure sshd_config from https://raw.githubusercontent.com/k4yt3x/sshd_config/master/sshd_config" | log "${REPORT_FILE}"

echo "Configuring the kernel..."
wget -O /etc/sysctl.conf https://raw.githubusercontent.com/k4yt3x/sysctl/master/sysctl.conf
echo "Fetched a secure sshd_config from https://raw.githubusercontent.com/k4yt3x/sysctl/master/sysctl.conf" | log "${REPORT_FILE}"

echo "Disabling USBs..."
printf "blacklist usb-storage\ninstall usb-storage /bin/true\n" > /etc/modprobe.d/cypat.blacklist.conf
echo "usb-storage has been added to the kernel blacklist" | log "${REPORT_FILE}"

echo "Removing/Quarantining bad files..."
for dir in /home /var /media /opt /run /opt
do
    while read file 
    do 
        echo "Found bad file at $file"
        if mv $file "/root/quarantine/cypat${file}" > /dev/null 
        then
            chown root:root "/root/quarantine/cypat${file}" > /dev/null
            chmod 0400 "/root/quarantine/cypat${file}" > /dev/null
            echo "Quarantined $file to /root/quarantine/cypat${file}"
        else
            echo "Failed to quarantine $file" | tee -a /dev/stderr
        fi
    done < <(find $dir -name "*.mp3" -o -name "*.ogg" -o -name "*.pcap" -o -name "*.pcapng" -o -name "*.mp4")
done | log "${REPORT_FILE}"

# TODO: mas

echo "Updating and restaring..."
apt-get update -y > /dev/null && apt-get upgrade -y
apt-get autoremove -y > /dev/null

echo "Ran apt-get and apt-get upgrade" | log "${REPORT_FILE}"

read -p "About to reboot, press enter to continue..." dummy
reboot now
