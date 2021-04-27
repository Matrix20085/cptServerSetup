#!/bin/bash


function pause(){
   read -p "$*"
}

echo "=========================== Updating OS ==========================="
apt update
apt -y upgrade
pause 'OS Updated'

echo "=========================== Installing Dependicies ==========================="
apt install -y nmap apache2 screen dnsutils
apt install -y procmail
pause 'Dependicies Installed'

echo "=========================== IPv6 Disabled ==========================="
cat <<-EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.eth1.disable_ipv6 = 1
net.ipv6.conf.ppp0.disable_ipv6 = 1
net.ipv6.conf.tun0.disable_ipv6 = 1
EOF

sysctl -p > /dev/null 2>&1

pause 'IPv6 Disabled'



echo "=========================== Changing Hostname ==========================="
read -p "Enter your hostname (NOT FQDN): " -r primary_hostname
read -p "Enter your hostname[.]FQDN (without brackets):  " -r primary_domain
read -p "Enter your External IP Address (or range):  " -r extIP

IFS="." read -ra values <<< "$primary_domain"
dName=${values[1]}
toplevel=${values[2]}
extip1=$(ip a |grep -E -iv '\slo|forever|eth0:1' | grep "inet" |cut -d" " -f6 |cut -d"/" -f1)
cat <<-EOF > /etc/hosts
127.0.1.1 $primary_hostname $primary_domain
127.0.0.1 localhost $primary_domain
EOF

cat <<-EOF > /etc/hostname
$primary_hostname
EOF

puase 'Hostname will change on reboot'


echo "=========================== Setting Up User Account ==========================="

echo $'\n'
read -p '[ ] What account will emails come from?  ' -r accountname
accountpassword=$(openssl rand -hex 10 | base64)
credentials="[ + ] ${accountname} password is:  ${accountpassword}"
topline="###########################################################################"
bottomline=$topline
echo $'\n';echo $topline
echo $credentials
echo $bottomline;echo $'\n'
adduser ${accountname} --quiet --force-badname --disabled-password --shell /usr/sbin/nologin --gecos "" > /dev/null 2>&1
echo "${accountname}:${accountpassword}" | chpasswd > /dev/null 2>&1
mkdir -p /home/${accountname}/mail
chown -R ${accountname}:${accountname} /home/${accountname}/
pause 'User Account Created'


echo "=========================== Generating SSL Certs ==========================="
if [ -d "/opt/letsencrypt/" ]
    then 
    echo $'\n';echo "[ + ] LetsEncrypt already installed.  ";echo $'\n'
    else 
    echo $'\nPlease be patient as we download any necessary files...'
    service apache2 stop
    apt-get update > /dev/null 2>&1
    apt-get install -y python-certbot-apache > /dev/null 2>&1
    git clone https://github.com/certbot/certbot.git /opt/letsencrypt > /dev/null 2>&1
fi

cd /opt/letsencrypt
letsencryptdomains=()
end="false"
i=0


cd /opt/letsencrypt

echo $'\n[!]\tThis script creates a wildcard certificate for all subdomains to your domain'
echo $'\n[!]\tJust enter your core domain name (e.g. github.com)'
echo $'\n'
read -p "Enter your server's domain:  " -r domain

command="certbot certonly --manual --register-unsafely-without-email --agree-tos --preferred-challenges dns -d '${domain},*.${domain}'"
eval $command
pause 'Cert Generated'


echo "=========================== Installing Mail Server ==========================="




password=$(openssl rand -hex 10 | base64)
adduser mailarchive --quiet --disabled-password --shell /usr/sbin/nologin --gecos "" > /dev/null 2>&1
echo "mailarchive:${password}" | chpasswd > /dev/null 2>&1
password2=$(openssl rand -hex 10 | base64)
adduser mailcheck --quiet --disabled-password --shell /usr/sbin/nologin --gecos "" > /dev/null 2>&1
echo "mailcheck:${password2}" | chpasswd > /dev/null 2>&1
echo $'\nInstalling Dependicies\n'
apt-get install -qq -y dovecot-common dovecot-imapd dovecot-lmtpd
apt-get install -qq -y postfix postgrey postfix-policyd-spf-python
apt-get install -qq -y opendkim opendkim-tools
apt-get install -qq -y opendmarc
apt-get install -qq -y mailutils
echo $'\n[ ] We use the "mailarchive" account to archive sent emails.\n'
echo $'###################################################################'                                                                 #'
echo "# [ + ] 'mailarchive' password is:  ${password}  #"
echo $'###################################################################\n'
echo $'\n[ ] We use the "mailcheck" account to verify any email problems.\n'
echo $'###################################################################'                                                                 #'
echo "# [ + ] 'mailcheck' password is:  ${password2}   #"
echo $'###################################################################\n'
read -p "Enter your mail server's domain (everything after the '@' sign): " -r primary_domain
echo $'\n'
#read -p "Enter IP's to allow Relay (if none just hit enter): " -r relay_ip
echo $'\n[ ] Configuring Postfix'

    cat <<-EOF > /etc/postfix/main.cf
smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_tls_cert_file=/etc/letsencrypt/live/${primary_domain}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/${primary_domain}/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = ${primary_domain}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = ${primary_domain}
mydestination = ${primary_domain}, localhost.com, , localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_command = procmail -a "\$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:12301,inet:localhost:54321
non_smtpd_milters = inet:12301,inet:localhost:54321
disable_vrfy_command = yes
smtp_tls_note_starttls_offer = yes
always_bcc = mailarchive@${primary_domain}
smtpd_discard_ehlo_keyword_address_maps = cidr:/etc/postfix/esmtp_access
notify_classes = bounce, delay, policy, protocol, resource, software
bounce_notice_recipient = mailcheck
delay_notice_recipient = mailcheck
error_notice_recipient = mailcheck
EOF

    cat <<-EOF >> /etc/postfix/esmtp_access
# Allow DSN requests from local subnet only
192.168.0.0/16  silent-discard
172.16.0.0/16   silent-discard
0.0.0.0/0   silent-discard, dsn
::/0        silent-discard, dsn
EOF

    cat <<-EOF >> /etc/postfix/master.cf
submission inet n       -       -       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_wrappermode=no
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination
  -o smtpd_sender_restrictions=reject_unknown_sender_domain
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
EOF

    echo "Configuring Opendkim"

    mkdir -p "/etc/opendkim/keys/${primary_domain}"
    mkdir -p "/etc/opendkim/debug"
    cp /etc/opendkim.conf /etc/opendkim.conf.orig

    cat <<-EOF > /etc/opendkim.conf
domain                              *
AutoRestart                     Yes
AutoRestartRate             10/1h
Umask                                   0002
Syslog                              Yes
SyslogSuccess                   Yes
LogWhy                              Yes
Canonicalization            relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts                   refile:/etc/opendkim/TrustedHosts
KeyFile                             /etc/opendkim/keys/${primary_domain}/mail.private
Selector                            mail
Mode                                    sv
PidFile                             /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                              opendkim:opendkim
Socket                              inet:12301@localhost
EOF

    cat <<-EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
${primary_domain}
EOF

cd "/etc/opendkim/keys/${primary_domain}" || exit
opendkim-genkey -b 1024 -s mail -d "${primary_domain}"
echo 'SOCKET="inet:12301"' >> /etc/default/opendkim
chown -R opendkim:opendkim /etc/opendkim

echo "Configuring opendmarc"

    cat <<-EOF > /etc/opendmarc.conf
AuthservID ${primary_domain}
PidFile /var/run/opendmarc/opendmarc.pid
RejectFailures false
Syslog true
TrustedAuthservIDs ${primary_domain}
Socket  inet:54321@localhost
UMask 0002
UserID opendmarc:opendmarc
IgnoreHosts /etc/opendmarc/ignore.hosts
HistoryFile /var/run/opendmarc/opendmarc.dat
EOF

mkdir "/etc/opendmarc/"
echo "localhost" > /etc/opendmarc/ignore.hosts
chown -R opendmarc:opendmarc /etc/opendmarc

echo 'SOCKET="inet:54321"' >> /etc/default/opendmarc

echo "Configuring Dovecot"

    cat <<-EOF > /etc/dovecot/dovecot.conf
log_path = /var/log/dovecot.log
auth_verbose=yes
auth_debug=yes
auth_debug_passwords=yes
mail_debug=yes
verbose_ssl=yes
disable_plaintext_auth = no
mail_privileged_group = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u
userdb {
  driver = passwd
}
passdb {
  args = %s
  driver = pam
}
protocols = "imap"
#protocol imap {
#  mail_plugins = " autocreate"
#}
#
#plugin {
#  autocreate = Trash
#  autocreate2 = Sent
#  autosubscribe = Trash
#  autosubscribe2 = Sent
#}
namespace inbox {
  inbox = yes
  mailbox Trash {
    auto = subscribe
    special_use = \Trash
  }
  mailbox Sent {
    auto = subscribe
    special_use = \Sent
  }
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}
ssl=required
ssl_cert=</etc/letsencrypt/live/${primary_domain}/fullchain.pem
ssl_key=</etc/letsencrypt/live/${primary_domain}/privkey.pem
EOF

    cat <<-EOF > /etc/pam.d/imap
#%PAM-1.0
auth    required        pam_unix.so nullok
account required        pam_unix.so
EOF

    cat <<-EOF > /etc/logrotate.d/dovecot
# dovecot SIGUSR1: Re-opens the log files.
/var/log/dovecot*.log {
  missingok
  notifempty
  delaycompress
  sharedscripts
  postrotate
    /bin/kill -USR1 `cat /var/run/dovecot/master.pid 2>/dev/null` 2> /dev/null || true
  endscript
}
EOF


echo "Restarting Services"
service postfix restart
service opendkim restart
service opendmarc restart
service dovecot restart

echo "Checking Service Status"
service postfix status
service opendkim status
service opendmarc status
service dovecot status

pause 'Mail Server Installed and Configured'


echo "=========================== Setting Up CobaltStrike Profiles ==========================="


read -p "Enter your DNS (A) record for domain [ENTER]: " -r domain
echo ""
password=$(openssl rand -hex 10 | base64)
cslocation="/root/cobaltstrike"
read -e -i "$cslocation" -p "Enter the folder-path to cobaltstrike [ENTER]: " -r cobaltStrike
cobaltStrike="${cobaltStrike:-$cslocation}"
echo

domainPkcs="$domain.p12"
domainStore="$domain.store"
cobaltStrikeProfilePath="$cobaltStrike/httpsProfile"

cd /etc/letsencrypt/live/$domain
echo '[Starting] Building PKCS12 .p12 cert.'
openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out $domainPkcs -name $domain -passout pass:$password
echo '[Success] Built $domainPkcs PKCS12 cert.'
echo '[Starting] Building Java keystore via keytool.'
keytool -importkeystore -deststorepass $password -destkeypass $password -destkeystore $domainStore -srckeystore $domainPkcs -srcstoretype PKCS12 -srcstorepass $password -alias $domain
echo '[Success] Java keystore $domainStore built.'
mkdir $cobaltStrikeProfilePath
cp $domainStore $cobaltStrikeProfilePath
echo '[Success] Moved Java keystore to CS profile Folder.'
cd $cobaltStrikeProfilePath
echo '[Starting] Cloning into amazon.profile for testing.'
wget https://raw.githubusercontent.com/rsmudge/Malleable-C2-Profiles/master/normal/amazon.profile --no-check-certificate -O amazon.profile
wget https://raw.githubusercontent.com/rsmudge/Malleable-C2-Profiles/master/normal/ocsp.profile --no-check-certificate -O ocsp.profile    
echo '[Success] ocsp.profile clonned.'
echo '[Starting] Adding java keystore / password to amazon.profile.'
echo " " >> amazon.profile
echo 'https-certificate {' >> amazon.profile
echo   set keystore \"$domainStore\"\; >> amazon.profile
echo   set password \"$password\"\; >> amazon.profile
echo '}' >> amazon.profile
echo '[Success] amazon.profile updated with HTTPs settings.'
echo '[Starting] Adding java keystore / password to oscp.profile.'
echo " " >> ocsp.profile
echo 'https-certificate {' >> ocsp.profile
echo   set keystore \"$domainStore\"\; >> ocsp.profile
echo   set password \"$password\"\; >> ocsp.profile
echo '}' >> ocsp.profile
echo '[Success] ocsp.profile updated with HTTPs settings.'


pause 'CobaltStrike profiles Generated'


echo "=========================== Setting DNS Entries ==========================="


read -p '[ ] What is your external IP?  ' -r extip
domain=$(ls /etc/opendkim/keys/ | head -1)
fields=$(echo "${domain}" | tr '.' '\n' | wc -l)
dkimrecord=$(cut -d '"' -f 2 "/etc/opendkim/keys/${domain}/mail.txt" | tr -d "[:space:]")
dkim2=$( echo ${dkimrecord} | sed -r 's/\+/\%2B/g' | sed -r 's/\=/\%3D/g' | sed -r 's/\;/\%3B/g' | sed -r 's/\//\%2F/g' )
dmarcTemp0="v=DMARC1; p=reject"
dmarcTemp1=$( echo ${dmarcTemp0} | sed -r 's/\=/\%3D/g' | sed -r 's/\;/\%3B/g' | sed -r 's/\ /\%20/g' )

if [[ $fields -eq 2 ]]; then
    fulldomain=$( cat /etc/hosts | cut -d"." -f5-6 | uniq )
    dName=$( cat /etc/hosts | cut -d"." -f5 | uniq )
    toplevel=$( cat /etc/hosts | cut -d"." -f6 | uniq )
    cat <<-EOF > dnsentries.txt
    DNS Entries for ${domain}:
    ====================================================================
    Namecheap - Enter under Advanced DNS
    Record Type: A
    Host: @
    Value: ${extip}
    TTL: 5 min
    Record Type: TXT
    Host: @
    Value: v=spf1 ip4:${extip} -all
    TTL: 5 min
    Record Type: TXT
    Host: mail._domainkey
    Value: ${dkimrecord}
    TTL: 5 min
    Record Type: TXT
    Host: ._dmarc
    Value: v=DMARC1; p=reject
    TTL: 5 min
    Change Mail Settings to Custom MX and Add New Record
    Record Type: MX
    Host: @
    Value: ${domain}
    Priority: 10
    TTL: 5 min
EOF

curl -v "https://api.namecheap.com/xml.response?ApiUser=${usernameValue}&ApiKey=${apikeyValue}&UserName=${usernameValue}&Command=namecheap.domains.dns.setHosts&ClientIp=${updateIP}&SLD=${dName}&TLD=${toplevel}&HostName1=@&RecordType1=A&Address1=${extip}&TTL1=300&HostName2=www&RecordType2=A&Address2=${extip}&TTL2=300&HostName3=mail&RecordType3=A&Address3=${extip}&TTL3=300&HostName4=@&RecordType4=MX&Address4=${fulldomain}&TTL4=300&MXPref4=10&EmailType=MX&HostName5=@&RecordType5=TXT&Address5=v=spf1+ip4:${extip}%20-all&TTL5=300&HostName6=mail._domainkey&RecordType6=TXT&Address6=${dkim2}&TTL6=300&HostName7=._dmarc&RecordType7=TXT&Address7=${dmarcTemp1}&TTL7=300&HostName8=temp&RecordType8=A&Address8=${extip}&TTL8=60"
cat dnsentries.txt