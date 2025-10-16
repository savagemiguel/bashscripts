#!/bin/bash
###########################################
# INTERACTIVE INSTALLATION SCRIPT #

# Function to handle script interruption
handle_interrupt() {
    echo -e "\nWARNING: Are you sure you want to cancel the script? (Y/n)"
    read -r cancel_choice
    if [[ "$cancel_choice" =~ ^[Yy]$ ]]; then
        echo "Script canceled by the user."
        exit 1
    else
        echo "Resuming script..."
    fi
}

# Create a dynamic OS version number list
supported_versions_list() {
    local start_major=20
    local start_minor=4
    local max_major=25
    local minor_versions=(04 10) # Ubuntu releases in April (.04) and October (.10)
    local max_point_release=5 # Maximum point releases (e.g., .1, .2, .3)

    echo "Supported Ubuntu Versions:"
    for ((major=start_major; major<=max_major; major++)); do
        for minor in "${minor_versions[@]}"; do
            # Skip versions less than 20.04
            if ((major == 20 && minor < start_minor)); then
                continue
            fi

            # Print the base version
            echo "- $major.$minor"

            # Add point releases for LTS versions (April releases only)
            if [[ "$minor" == "04" ]]; then
                for ((point=1; point<=max_point_release; point++)); do
                    echo "- $major.$minor.$point"
                done
            fi
        done
    done
}

# Trap Ctrl+C (SIGINT) and call the interrupt handler
trap handle_interrupt SIGINT

umask 0022

# Log file
LOG_FILE="/var/log/phynx-mail-setup.log"
exec > >(tee -a $LOG_FILE) 2>&1

# Dry run mode
DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    echo "Dry run mode enabled. No changes will be made."
fi

# Function to check the success of the last command
check_success() {
    if [ $? -ne 0 ]; then
        echo "ERROR: $1"
        exit 1
    fi
}

# Function to execute commands conditionally based on dry run mode
execute() {
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] $@"
    else
        eval "$@"
        check_success "Failed to execute: $@"
    fi
}

# Function to display a progress bar
show_progress() {
    local duration=$1
    local interval=0.1
    local steps=$(echo "$duration / $interval" | bc) # Use bench calculator (bc) for floating-point division in bash
    local progress=0

    while [ $progress -lt $steps ]; do
        printf "\r["
        for ((i = 0; i < $steps; $i++)); do
            if [ $i -le $progress ]; then
                printf "="
            else
                printf " "
            fi
        done
        print "] %d%%" $((progress * 100 / steps))
        sleep $interval
        progress=$((progress + 1))
    done
    printf "\n"
}

# Function to automatically update the script
update_script() {
    echo "Downloading the latest version of the script..."
    local script_url="https://example.com/phynx-mail-latest.sh"
    local temp_file="/tmp/phynx-mail-latest.sh"

    curl -s -o "$temp_file" "$script_url"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to download the latest version. Please update manually."
        return 1
    fi

    chmod +x "$temp_file"
    mv "$temp_file" "$0"
    echo "Script updated successfully. Please re-run the script."
    exit 0
}

# Define script version
VERSION="1.0.0"

check_a_record() {
    # Prompt the user for FQDN
    while true; do
        read -p "Enter the domain name without the www. you'd like to check (subdomain 'mail' will automatically be added): " fqdn
        if [[ "$fqdn" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            break  # Exit the loop if the domain name is valid
        else
            echo "Invalid domain name. Please use a valid domain name."
        fi
    done

    mailfqdn="mail.$fqdn"
    server_ip=$(hostname -I | awk '{print $1}')

    # Array of domains to check
    local domains=("$mailfqdn" "$fqdn")
    for domain in "${domains[@]}"; do
        # Resolve all A records for the domain
        local resolved_ips
        resolved_ips=$(host -t A "$domain" 2>/dev/null | awk '/has address/ { print $4 }')

        if [[ -z "$resolved_ips" ]]; then
            echo "ERROR: No A record found for $domain."
            echo "Please fix this and rerun the installation."
            return 1
        fi

        # Convert space-separated IPs to comma-separated with a space
        local resolved_ips_formatted
        resolved_ips_formatted=$(echo "$resolved_ips" | tr ' ' ',' | sed 's/,/, /g')

        # Display all resolved IPs
        echo "Resolved IPs for $domain: $resolved_ips_formatted"

        # Check if $server_ip is in the list of resolved IPs
        if echo "$resolved_ips" | grep -q "$server_ip"; then
            echo "SUCCESS: A record for $domain includes the server IP ($server_ip)."
        else
            echo "ERROR: A record for $domain does not include the server IP ($server_ip)."
            echo "Please fix this and rerun the installation."
            return 1
        fi
    done

    return 0  # All checks passed
}

# Help and version menu
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: ./phynx-mail.sh [options]"
    echo "Options:"
    echo "  --dry-run            Run the script in dry-run mode without making changes."
    echo "  --uninstall          Uninstall the mail server, installed packages and clean up configuration files."
    echo "  -h, --help           Display this help menu."
    echo "  -v, --version        Display the script version."
    echo "  -os, --os-version    Display the supported OS(s) and version(s)."
    echo "  -A, --dns            Check A records in the DNS to see if they're updated yet."
    exit 0
fi

# Check if the user wants to update
if [ "$1" = "--update" ]; then
    update_script
fi

# Check installation script version number
if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    echo "Phynx Mail v$VERSION"
    exit 0
fi

# Handle --os-version flag
if [[ "$1" == "--os-version" || "$1" == "-os" ]]; then
    echo "Supported OS: Ubuntu"
    echo "Supported Versions:"
    supported_versions_list
    exit 0
fi

# Handle -A / --dns flag
if [[ "$1" == "-A" || "$1" == "--dns" ]]; then
    check_a_record
    exit 0
fi

# Implement semantic versioning
compare_versions() {
    local v1=$(echo "$1" | awk -F. '{ printf("%d%03d%03d\n", $1, $2, $3); }')
    local v2=$(echo "$2" | awk -F. '{ printf("%d%03d%03d\n", $1, $2, $3); }')

    if [ "$v1" -lt "$v2" ]; then
        return 1  # v1 < v2
    elif [ "$v1" -gt "$v2" ]; then
        return 2  # v1 > v2
    else
        return 0  # v1 == v2
    fi
}

# Enhance logging for version checks
# Add error handling for version check
# Update version check to parse JSON
# Enhance error handling for jq not found during version check
check_latest_version() {
    echo "Checking for the latest version..." | tee -a "$LOG_FILE"
    local retries=3
    local latest_version=""
    local release_notes=""
    local changelog=""

    for ((i=1; i<=retries; i++)); do
        if ! command -v jq >/dev/null 2>&1; then
            echo "ERROR: Unable to check for the latest version after $i attempts. 'jq' is not installed." | tee -a "$LOG_FILE"
            echo "'jq' is a lightweight and flexible command-line JSON processor, which is required for parsing JSON to check the version for updates." | tee -a "$LOG_FILE"
            read -p "Would you like to install 'jq' now? (Y/n): " install_jq_choice
            if [[ "$install_jq_choice" =~ ^[Yy]$ ]]; then
                execute "apt-get install -y -qq jq"
            else
                echo "'jq' is required for version checking. Please install it manually and re-run the script." | tee -a "$LOG_FILE"
                exit 1
            fi
        fi

        local response=$(curl -s https://raw.githubusercontent.com/savagemiguel/bashscripts/refs/heads/phynx-mail/phynx-mail-latest-version.json || echo "")
        if [ -n "$response" ]; then
            latest_version=$(echo "$response" | jq -r '.latest_version')
            release_notes=$(echo "$response" | jq -r '.release_notes')
            changelog=$(echo "$response" | jq -r '.changelog')
            break
        fi
        echo "Attempt $i of $retries failed. Retrying..." | tee -a "$LOG_FILE"
        sleep 2
    done

    if [ -z "$latest_version" ]; then
        echo "ERROR: Unable to check for the latest version after $retries attempts. Proceeding with the current version: $VERSION." | tee -a "$LOG_FILE"
        return
    fi

    compare_versions "$VERSION" "$latest_version"
    case $? in
        1)
            echo "WARNING: You are using version $VERSION, but the latest version is $latest_version." | tee -a "$LOG_FILE"
            echo "Release Notes: $release_notes" | tee -a "$LOG_FILE"
            echo "Changelog: $changelog" | tee -a "$LOG_FILE"
            echo "Please update the script to the latest version before proceeding." | tee -a "$LOG_FILE"
            read -p "Do you want to update now? (Y/n): " update_choice
            if [[ "$update_choice" =~ ^[Yy]$ ]]; then
                update_script
            fi
            ;;
        2)
            echo "You are using a newer version ($VERSION) than the latest released version ($latest_version)." | tee -a "$LOG_FILE"
            ;;
        0)
            echo "You are using the latest version: $VERSION." | tee -a "$LOG_FILE"
            ;;
    esac
}

# Call the version check function at the start of the script
check_latest_version
sleep 2

check_distro() {
    # Detect Linux distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_VERSION_ID="$VERSION_ID"

        # Define supported OS and version
        case "$DISTRO_ID" in
            ubuntu)
                if (( $(echo "$DISTRO_VERSION_ID >= 20.04" | bc -l) )); then
                    echo "You are running a supported OS version. To see a list of supported OS(s) and versions, please use --os-version or -os"
                fi
                ;;
            *)
                echo "You are currently on an unsupported version of Linux to run this script. Please use --os-version or -os for a list of supported versions."
                ;;
        esac
    else
        echo "ERROR /etc/os-release not found. Cannot determine OS details."
    fi
}

# Call the distro checker function
check_distro
sleep 2

# Step 1 Check dependencies
echo "Step 1: Checking dependencies..."
required_commands=("host" "awk" "apt-get")
for cmd in "${required_commands[@]}"; do
    if ! command -v $cmd >/dev/null 2>&1; then
        echo "ERROR: Required command '$cmd' is not installed. Please install it and try again."
        exit 1
    fi
done
echo "All required dependencies are installed."
sleep 2

# Step 2: Prompt for hostname and configure mailfqdn
echo "Step 2: Configuring hostname..."
echo "The mail subdomain will automatically be added."
read -p "Enter the domain name for the mail server without the www. (e.g., example.com): " fqdn
# Validate domain name
if [[ ! "$fqdn" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "Invalid domain name. Please use a valid domain name."
    exit 0
fi

sub_domain="mail"
mailfqdn="$sub_domain.$fqdn"

# Step 3: Retrieve server IP
echo "Step 3: Detecting server IP..."
server_ip=$(hostname -I | awk '{print $1}')
check_success "Failed to retrieve server IP."
echo "Detected server IP: $server_ip"

# Check if A record for the FQDN matches the server IP
resolved_ip=$(host -t A "$mailfqdn" 2>/dev/null | awk '/has address/ { print $4 }')

if [[ -z "$resolved_ip" ]]; then
    echo "ERROR: No A record found for $mailfqdn."
    echo "Please ensure the domain points to the server IP ($server_ip) and try again."
    echo "You can use the -A or --dns flag when running the installation to check."
    exit 1
fi

if echo "$resolved_ip" | grep -q "$server_ip"; then
    echo "SUCCESS: A record for $mailfqdn includes the server IP ($server_ip)."
else
    echo "ERROR: A record for $mailfqdn does not include the server IP ($server_ip)."
    echo "Resolved IP(s) for $mailfqdn: $resolved_ip"
    echo "Please update the DNS records to point $mailfqdn to $server_ip and try again."
    echo "You can use the -A or --dns flag when running the installation to check."
    exit 1
fi
sleep 2

echo "Configured mail server FQDN: $mailfqdn"
sleep 2

hostnamectl set-hostname $fqdn
echo "Changed hostname to $fqdn"
sleep 2

# Step 4: Install required packages
echo "Step 4: Installing required packages..."

# Define array of packages required for installation
required_packages=("opendkim" "opendkim-tools" "postfix" "postfix-pcre" "dovecot-core" "dovecot-sieve" "dovecot-imapd" "dovecot-pop3d" "spamassassin" "spamc" "spamd" "wget" "curl" "net-tools" "fail2ban" "bind9-host" "mailutils" "apache2" "certbot" "python3" "python3-certbot-apache")

# Loop through packages and install individually
for pkg in "${required_packages[@]}"; do
    echo "Installing $pkg..."
    sudo apt-get install -y -qq "$pkg"

    # Check if installation of each package is successful
    if [ $? -eq 0 ]; then
        echo "$pkg installed successfully."
    else
        echo "Failed to install $pkg."
    fi
done
echo "All required packages have been installed successfully."

# Step 5: Prompt for SSL certificate configuration
echo "Step 5: SSL certificate configuration..."
read -p "Do you want to configure an SSL certificate? (Y/n): " ssl_choice
if [[ "$ssl_choice" =~ ^[Yy]$ ]]; then
    read -p "Please enter the email you'd like to use: " ssl_email
    sleep 2
    certbot certonly --expand --apache -d $fqdn -d $mailfqdn --email $ssl_email --agree-tos --deploy-hook "echo \"$RENEWED_DOMAINS\" | grep -q '$mailfqdn' && service postfix reload && service dovecot reload"
else
    echo "Skipping SSL certificate generation. You can generate your own SSL certificate later on."
fi

# Step 6: Prompt for IPv6 usage
echo "Step 6: Checking IPv6 configuration..."
read -p "Will you use IPv6? (y/N): " ipv6_choice
if [[ "$ipv6_choice" =~ ^[Yy]$ ]]; then
    ipv6=$(host "$fqdn" | grep "IPv6" | awk '{print $NF}')
    if [ -z "$ipv6" ]; then
        echo "\033[0;31mIf you use IPv6, please make sure your domain ($fqdn) is pointed to $ipv6 before you continue.\033[0m"
        exit 0
    fi
else
    ipv6=""
fi

# Step 7: Customize variables
echo "Step 7: Customizing configuration..."
read -p "Enter the mailbox directory (default: maildir): " mailbox_dir
mailbox_dir=${mailbox_dir:-maildir}

read -p "Enter the allowed protocols (default: imap pop3): " protocol
protocol=${protocol:-"imap pop3"}

read -p "Enter the ports to open (default: 25, 80, 110, 465, 587, 993, 995): " ports
ports=${ports:-"25 80 110 465 587 993 995"}

# Convert the $ports variable into an array
IFS=' ' read -r -a ports_array <<< "$ports"

# Open the required ports
for port in "${ports_array[@]}"; do
    echo "Opening port $port..."
    sudo ufw allow "$port" 2>/dev/null

    # Check if the ports are opened successfully or not
    if [ $? -eq 0 ]; then
        echo "Port $port opened successfully."
    else
        echo "Failed to open port $port. Please contact your server administrator to open the required ports, then rerun the installation."
    fi
done
ufw allow 'Apache Full'
systemctl enable apache2
systemctl stop apache2
sleep 2

# Certbot directory
cert_dir="/etc/letsencrypt/live/$mailfqdn"

# Additional variables to add to mydestination
postconf -e "myhostname = $mailfqdn"
postconf -e "mail_name = $fqdn" # SMTP banner
postconf -e "mydomain = $fqdn"
postconf -e 'mydestination = $myhostname, $mydomain, mail, localhost.localdomain, localhost, localhost.$mydomain'

# Move the cert & key files to the default location of Let's Encrypt
postconf -e "smtpd_tls_key_file=$cert_dir/privkey.pem"
postconf -e "smtpd_tls_cert_file=$cert_dir/fullchain.pem"

# TLS conf and variables
postconf -e 'smtpd_tls_security_level = may'
postconf -e 'smtp_tls_security_level = may'

# TLS is required for authentication
postconf -e 'smtpd_tls_auth_only = yes'

# Exclude insecure and obsolete encryption protocols.
postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
postconf -e 'smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
postconf -e 'smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'

# Exclude suboptimal ciphers.
if [ "$allow_ciphers" = "no" ]; then
	postconf -e 'tls_preempt_cipherlist = yes'
	postconf -e 'smtpd_tls_exclude_ciphers = aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, eNULL'
fi

# Tell Postfix to look for Dovecot authentication for usernames and passwords
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'

# HELO, Sender, Relay and Recipient restrictions
postconf -e "smtpd_sender_login_maps = pcre:/etc/postfix/login_maps.pcre"
postconf -e 'smtpd_sender_restrictions = reject_sender_login_mismatch, permit_sasl_authenticated, permit_mynetworks, reject_unknown_reverse_client_hostname, reject_unknown_sender_domain'
postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination, reject_unknown_recipient_domain'
postconf -e 'smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination'
postconf -e 'smtpd_helo_required = yes'
postconf -e 'smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname'

# Home mailbox directory
postconf -e 'home_mailbox = Mail/Inbox/'

# Turn off "Received From:" headers in sent emails
postconf -e "header_checks = regexp:/etc/postfix/header_checks"
echo "/^Received:.*/ IGNORE
      /^X-Originating-IP:/  IGNORE" >> /etc/postfix/header_checks

# Use login map to ensure the sender is authenticated as the sender
echo "/^(.*)@$(sh -c "echo $fqdn | sed 's/\./\\\./'")$/   \${1}" > /etc/postfix/login_maps.pcre

echo "Configuring Postfix..."
sed -i '/^\s*-o/d;/^\s*submission/d;/^\s*smtp/d' /etc/postfix/master.cf
echo "smtp unix - - n - - smtp
smtp inet n - y - - smtpd
  -o content_filter=spamassassin
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_tls_auth_only=yes
  -o smtpd_enforce_tls=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_sender_login_mismatch
  -o smtpd_sender_login_maps=pcre:/etc/postfix/login_maps.pcre
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject_unauth_destination
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
spamassassin unix -     n       n       -       -       pipe
  user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f \${sender} \${recipient}" >> /etc/postfix/master.cf

# Backup Dovecot config
mv /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak
sleep 2

echo "Configuring Dovecot..."
echo "
# Dovecot config
ssl = required
ssl_cert = <$cert_dir/fullchain.pem
ssl_key = <$cert_dir/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = "'EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA256:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EDH+aRSA+AESGCM:EDH+aRSA+SHA256:EDH+aRSA:EECDH:!aNULL:!eNULL:!MEDIUM:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!SEED'"
ssl_prefer_server_ciphers = yes
ssl_dh = </usr/share/dovecot/dh.pem
auth_mechanisms = plain login
auth_username_format = %n
protocols = \$protocols $protocol

# Find valid users in /etc/passwd
userdb {
    driver = passwd
}

# Fallback... Use PAM
passdb {
    driver = pam
}

# Mailbox locations
mail_location = $mailbox_dir:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs

# Namespaces
namespace inbox {
    inbox = yes
    mailbox Drafts {
        special_use = \\Drafts
        auto = subscribe
    }
    
    mailbox Junk {
        special_use = \\Junk
        auto = subscribe
        autoexpunge = 30d
    }
    
    mailbox Sent {
        special_use = \\Sent
        auto = subscribe
    }

    mailbox Trash {
        special_use = \\Trash
    }

    mailbox Archive {
        special_use = \\Archive
    }
}

# Let Postfix use Dovecot's authentication system
service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0660
        user = postfix
        group = postfix
    }
}

protocol lda {
    mail_plugins = \$mail_plugins sieve
}

protocol lmtp {
    mail_plugins = \$mail_plugins sieve
}

protocol pop3 {
    pop3_uidl_format = %08Xu%08Xv
    pop3_no_flag_updates = yes
}

plugin {
    sieve = ~/.dovecot.sieve
    sieve_default = /var/lib/dovecot/sieve/default.sieve
    #sieve_global_path = /var/lib/dovecot/sieve/default.sieve
    sieve_dir = ~/.sieve
    sieve_global_dir = /var/lib/dovecot/sieve/
}
" > /etc/dovecot/dovecot.conf

# For older versions of Dovecot, remove ssl_dl
case "$(dovecot --version)" in
    1|2.1*|2.2*) sed -i '/^ssl_dh/d' /etc/dovecot/dovecot.conf ;;
esac

mkdir /var/lib/dovecot/sieve/

echo "require [\"fileinto\", \"mailbox\"];
if header :contains \"X-Spam-Flag\" \"YES\"
	{
		fileinto \"Junk\";
	}" > /var/lib/dovecot/sieve/default.sieve

grep -q '^vmail:' /etc/passwd || useradd vmail
chown -R vmail:vmail /var/lib/dovecot
sievec /var/lib/dovecot/sieve/default.sieve

echo 'Preparing user authentication...'
grep -q nullok /etc/pam.d/dovecot ||
echo 'auth    required        pam_unix.so nullok
account required        pam_unix.so' >> /etc/pam.d/dovecot
sleep 2

# OpenDKIM
echo "Generating OpenDKIM keys..."
groupadd opendkim
mkdir -p "/etc/postfix/dkim/$fqdn"
/usr/sbin/opendkim-genkey -D "/etc/postfix/dkim/$fqdn" -d "$fqdn" -s "$mailfqdn"
chgrp -R opendkim /etc/postfix/dkim/*
chmod -R g+r /etc/postfix/dkim/*

echo "Generating OpenDKIM info..."

grep -q "$fqdn" /etc/postfix/dkim/keytable 2>/dev/null ||
echo "$mailfqdn._domainkey.$fqdn $fqdn:$mailfqdn:/etc/postfix/dkim/$fqdn/$mailfqdn.private" >> /etc/postfix/dkim/keytable

grep -q "$fqdn" /etc/postfix/dkim/signingtable 2>/dev/null ||
echo "*@$fqdn $mailfqdn._domainkey.$fqdn" >> /etc/postfix/dkim/signingtable

grep -q '127.0.0.1' /etc/postfix/dkim/trustedhosts 2>/dev/null ||
echo '127.0.0.1
     '"$server_ip"'' >> /etc/postfix/dkim/trustedhosts

grep -q '^KeyTable' /etc/opendkim.conf 2>/dev/null ||
echo 'KeyTable file:/etc/postfix/dkim/keytable
      SigningTable refile:/etc/postfix/dkim/signingtable
      InternalHosts refile:/etc/postfix/dkim/trustedhosts' >> /etc/opendkim.conf

grep -q '^Canonicalization' /etc/opendkim.conf 2>/dev/null ||
echo 'Canonicalization relaxed/simple' >> /etc/opendkim.conf

grep -q '^Socket\s*inet:12301@localhost' /etc/opendkim.conf ||
echo 'Socket inet:12301@localhost' >> /etc/opendkim.conf
sleep 2

# Add needed settings for OpenDKIM to Postfix conf
echo "Configuring Postfix with OpenDKIM settings..."
postconf -e 'smtpd_sasl_security_options = noanonymous, noplaintext'
postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
postconf -e "myhostname = $mailfqdn"
postconf -e 'milter_default_action = accept'
postconf -e 'milter_protocol = 6'
postconf -e 'smtpd_milters = inet:localhost:12301'
postconf -e 'non_smtpd_milters = inet:localhost:12301'
postconf -e 'mailbox_command = /usr/lib/dovecot/deliver'
postconf -e 'smtpd_forbid_bare_newline = normalize'
postconf -e 'smtpd_forbid_bare_newline_exclusions = $mynetworks'

# OpenDKIM PID file fix
/usr/lib/opendkim/opendkim.service.generate
systemctl daemon-reload
sleep 2

# Enable Fail2Ban security
[ ! -f /etc/fail2ban/jail.d/phynxmail.local ] && echo "
[postfix]
enabled = true

[postfix-sasl]
enabled = true

[sieve]
enabled = true

[dovecot]
enabled = true" > /etc/fail2ban/jail.d/phynxmail.local
sed -i "s|^backend = auto$|backend = systemd|" /etc/fail2ban/jail.conf

# Enable SpamAssassin cronjob for weekly updates
if [ -f /etc/default/spamassassin ]
then
    sed -i "s|^CRON=0|CRON=1|" /etc/default/spamassassin
    printf "Restarting SpamAssassin..."
    service spamassassin restart && printf " DONE\n"
    systemctl enable spamassassin
    sleep 2
elif [ -f /etc/default/spamd ]
then
    sed -i "s|^CRON=0|CRON=1|" /etc/default/spamd
    printf "Restarting SPAMD..."
    service spamd restart && printf " DONE \n"
    systemctl enable spamd
    sleep 2
else
    printf "ERROR: /etc/default/spamassassin or /etc/default/spamd do NOT exist. Make sure they're installed before proceeding.\n"
    exit 1
fi

for process in opendkim dovecot postfix fail2ban; do
    printf "Restarting %s..." "$process"
    service "$process" restart && printf " DONE\n"
    systemctl enable "$process"
    sleep 2
done

# Create DNS records for template examples
pval="$(tr -d '\n' <"/etc/postfix/dkim/$fqdn/$mailfqdn.txt" | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o 'p=.*')"
dkim_entry="$mailfqdn._domainkey.$fqdn   TXT v=DKIM1; k=rsa; $pval"
dmarc_entry="_dmarc.$fqdn   TXT v=DMARC1; p=reject; rua=mailto:postmaster@$fqdn; fo=1"
spf_entry="$fqdn   TXT v=spf1 mx a:$fqdn ipv4:$ipv4 -all"
mx_entry="$fqdn   MX 10 $mailfqdn 200"
sleep 2

# Create postmaster user and add to mail group
useradd -m -G mail postmaster
sleep 2

# Create a new cronjob that deletes old emails past certain day count
cat <<EOF > /etc/cron.weekly/postmaster-clean
#!/bin/bash

# Weekly Postmaster Cleaning CRON
find /home/postmaster/Mail -type f -mtime +30 -name '*.mail*' -delete >/dev/null 2>&1
exit 0
EOF

# Give proper permissions
chmod 755 /etc/cron.weekly/postmaster-clean

# Deploy hooks
#grep -q '^deploy-hook = echo "$RENEWED_DOMAINS" | grep -q' /etc/letsencrypt/cli.ini ||
#echo "deploy-hook = echo \"\$RENEWED_DOMAINS\" | grep -q '$mailfqdn' && service postfix reload && service dovecot reload" >> /etc/letsencrypt/cli.ini
#sleep 2

echo "INFO: Entries will appear different depending on your domain name's registrar DNS settings. These are to be used as guides or 'templates'.
$dkim_entry
$dmarc_entry
$spf_entry
$mx_entry" > "$HOME/phynxmail_dns"
sleep 2

printf "
ADD THESE RECORDS TO YOUR DNS TXT RECORDS:
$dkim_entry
$dmarc_entry
$spf_entry
$mx_entry

THESE ARE SAVED TO '~/phynxmail_dns' FOR REFERENCE

IMPORTANT: IF YOU CHOSE TO USE A LET'S ENCRYPT SSL CERTIFICATE, PLEASE MAKE SURE YOU HAVE YOUR EMAIL SERVER'S A AND MX RECORDS POINTING TO THIS SERVER BEFORE RUNNING THE FOLLOWING COMMAND:

certbot certonly --standalone -d $fqdn -d $mailfqdn --agree-tos

AFTER SUCCESSFULLY OBTAINING YOUR SSL CERTIFICATE, REMEMBER TO RESTART POSTFIX AND DOVECOT:
systemctl restart postfix dovecot

"
sleep 2

# Step 9: Post-installation summary
echo "Post-installation Summary:"
echo "Server IP: $server_ip"
echo "Hostname: $fqdn"
echo "SSL Configured: $cert_config"
echo "IPv6 Address: ${ipv6:-None}"
echo "Mailbox Directory: $mailbox_dir"
echo "Allowed Protocols: $protocol"
echo "Open Ports: $ports"
echo "Installation completed successfully. Please verify the configuration and restart the necessary services."



# Step 11 Send test email
send_test_email() {
    echo "Sending test email..."

    # Define test email parameters
    local test_email="test@example.com"
    local subject="Test Email from Mail Server"
    local body="This is a test email sent from the mail server."

    # Use the mail command to send the email
    echo "$body" | mail -s "$subject" "$test_email"

    if [ $? -eq 0 ]; then
        echo "Test email sent successfully to $test_email."
    else
        echo "Failed to send test email. Please check your mail server configuration."
    fi
}

# Call the function at the end of the script
send_test_email

# Step 11: Backup existing configuration
backup_configuration() {
    echo "Backing up existing configuration files..."

    # Define backup directory
    local backup_dir="/var/backups/phynx-mail-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"

    # List of configuration files to back up
    local config_files=(
        "/etc/postfix"
        "/etc/dovecot"
        "/etc/opendkim"
    )

    # Copy files to backup directory
    for file in "${config_files[@]}"; do
        if [ -e "$file" ]; then
            cp -r "$file" "$backup_dir"
            echo "Backed up: $file"
        else
            echo "Skipped: $file (not found)"
        fi
    done

    echo "Backup completed. Files saved to: $backup_dir"
}

# Call the function for backup
backup_configuration

# Step 12: Environment-specific adjustments
detect_environment() {
    echo "Detecting environment..."

    # Check if running in Docker
    if [ -f "/.dockerenv" ]; then
        echo "Environment: Docker"
        # Adjust configurations for Docker
        execute "sed -i 's/^inet_interfaces = all/inet_interfaces = loopback-only/' /etc/postfix/main.cf"
        echo "Adjusted Postfix configuration for Docker."
    fi

    # Check if running on AWS
    if curl -s http://169.254.169.254/latest/meta-data/ > /dev/null; then
        echo "Environment: AWS"
        # Adjust configurations for AWS
        execute "sed -i 's/^#disable_dns_lookups = yes/disable_dns_lookups = yes/' /etc/dovecot/dovecot.conf"
        echo "Adjusted Dovecot configuration for AWS."
    fi

    echo "Environment detection and adjustments completed."
}

# Call the function to change whatever is needed based on environment
# detect_environment

# Step 13: Localization support
# localize() {
#    local lang_file="/etc/phynx-mail/lang/en.lang"
#    if [ -n "$LANG" ]; then
#        lang_file="/etc/phynx-mail/lang/${LANG:0:2}.lang"
#    fi
#
#    if [ -f "$lang_file" ]; then
#        source "$lang_file"
#        echo "Localization loaded: ${LANG:0:2}"
#    else
#        echo "Localization file not found. Defaulting to English."
#    fi
#}

# Example usage of localization
# localize

# Replace echo statements with localized variables
# echo "${MSG_WELCOME:-Welcome to the Phynx Mail Setup Script!}"



# Step: Uninstallation option
if [ "$1" = "--uninstall" ]; then
    echo "Uninstalling mail server..."

    # Stop services
    echo "Stopping services..."
    execute "systemctl stop postfix dovecot opendkim"

    # Remove installed packages
    echo "Removing installed packages..."
    execute "$package_manager remove -y postfix postfix-pcre dovecot-core dovecot-sieve dovecot-imapd dovecot-pop3d opendkim opendkim-tools spamassassin spamc spamd net-tools fail2ban bind9-host"

    # Remove configuration files
    echo "Removing configuration files..."
    execute "rm -rf /etc/postfix /etc/dovecot /etc/opendkim /var/spool/postfix /var/mail"

    # Remove log files
    echo "Removing log files..."
    execute "rm -f $LOG_FILE"

    echo "Uninstallation completed successfully."
    exit 0
fi
