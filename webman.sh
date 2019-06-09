#!/bin/bash
# Tested with Ubuntu 18.04. nGinx PHP 7.3
ssldir=/etc/nginx/ssl
backupdir=/var/www/backups
webdir=/var/www
webuser=www-data:www-data
logfile=logs/webman.log
logger () {
if [ ! -d logs ]; then
        mkdir logs && touch "$logfile"
fi
# Helps with creating a log of all actions performed.
  echo -e "$(date +%a-%b-%d@%T): ${1}" >> "${logfile}"
}
confirmcommand () {
# Helps confirm the use of a dangerous or irreversible command.
  while :
  do
  echo "This is a potentially dangerous or irreversible command."
  read -r -p "Are you sure you wish to $1?" ccmnd
  case $ccmnd in
  [Yy]* ) break ;;
  [Nn]* ) exit 1;;
  * ) echo "Please enter only yes or no. (y/n)"
  esac
  done
}
wordpress () {
# Downloads the latest version of wordpress and unpacks it.
  wget https://wordpress.org/latest.tar.gz
  tar -xvf latest.tar.gz
  curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o wordpress/wp-cli.phar
  sudo chown -R ${webuser} wordpress/ && echo -e "Fixed Ownership.\\n"
  rm latest.tar.gz
  echo "Downloaded and extrated latest version of wordpress and wp-cli."
  logger "Downloaded and extracted latest version of wordpress and wp-cli."
  read -p -r "Press any key to continue."
}
nextcloud () {
# Downloads the latest version of nextcloud and unpacks it.
  wget https://download.nextcloud.com/server/releases/latest.zip
  unzip latest.zip
  chown -R ${webuser} nextcloud/ && echo -e "Fixed Ownership.\\n"
  rm latest.zip
  echo "Downloaded and extracted latest version of nextcloud."
  logger "Downloaded and extracted latest version of nextcloud."
  read -p -r "Press any key to continue."
}
netdata () {
  confirmcommand "Install NetData Monitoring system"
  bash <(curl -Ss https://my-netdata.io/kickstart.sh) all
  echo "Installed NetData monitoring system."
  logger "Installed NetData monitoring system."
  read -p -r "Press any key to continue."
}
letsencrypt () {
  install_le() {
    confirmcommand "Install LetsEncrypt SSL tools"
    add-apt-repository ppa:certbot/certbot && apt update
    echo -e "Let's encrypt supports apache and nginx.\\nWhich would you like to install?\\n1: Apache\\n2: nGinx"
    read -r version
    case $version in
    1) apt install python-certbot-apache
       echo -e "Installed Certbot for Apache."
       logger "Installed Certbot for Apache.";;
    2) apt install python-certbot-nginx
       echo -e "Installed Certbot for nGinx."
       logger "Installed Certbot for nGinx.";;
    *) echo -e '\nI'\'m not sure I got that. Come Again'\?';;
    esac
  }
  issuecert() {
  #Sets up LetsEncrypt and automatic renewal.
  echo -e 'Please follow the on-screen prompts to issue a new certificate.\n'
  if [ -z "$1" ]
  	then
  	echo "Please supply the public html folder of your domain. (not including ${webdir})"
  	else
  	if [ -z "$2" ]
  		then
  		echo 'Please supply the domain for LetsEncrypt to issue acertificate to.'
  		else
  	    certbot run -a webroot -i nginx --rsa-key-size 4096 -w "${webdir}/${arg1}" -d "${2}" -d "www.${arg2}"
  	fi
  fi
  }
  echo -e ' ############################################################################'
  echo -e ' ##                                                                        ##'
  echo -e ' ## install - Installs certbot and appropriate plugin.                     ##'
  echo -e ' ## issue <domain_folder> <domain_name> - Issues certificates for domain.  ##'
  echo -e ' ## renew - Manually renews all active certificates.                       ##'
  echo -e ' ##                                                                        ##'
  echo -e ' ############################################################################'
  read -r lenc arg1 arg2
  case $lenc in
    1) install_le;;
    2) issuecert "$arg1" "$arg2";;
    3) certbot renew;;
    *) echo -e '\nI'\'m not sure I got that. Come Again'\?';;
  esac
  read -p -r "Press any key to continue."
}
rlws () {
# Reloads all web services.
  service nginx reload
  service php7.3-fpm reload
  service mysql reload
  echo "Web services have been reloaded."
  logger "Web services have been reloaded."
  read -p -r "Press any key to continue."
}
rws () {
# Restarts all web services.
  service nginx restart
  service php7.3-fpm restart
  service mysql restart
  echo "Web services have been restarted."
  logger "Web services have been restarted"
  read -p -r "Press any key to continue."
}
backup () {
# Makes a full backup of the specified directory, including subdirs.
  clear
  if [ ! -d "${backupdir}" ]; then
  mkdir -p "${backupdir}"
  fi
  if [ -z "$1" ]; then
  echo -e "You must supply a name to save the file as.\\n"
  sleep 2
  else
  if [ -z "$2" ]; then
  echo -e "You must supply a directory to make a backup of.\\n"
  sleep 2
  else
  env GZIP=-9 tar -cvzf "${backupdir}/$1.tar.gz" -C "$2" .
  logger "Backup of $2 completed."
  read -p -r "Press any key to continue."
  fi
  fi
}
bws () {
# Creates a full backup of the webserver, including sql.
  mysqldump -u root --all-databases | tee "alldb-backup-$(date +%a-%b-%d@%T).sql"
  backup "full-web-backup" "${webdir}"
  echo "Backup completed successfully."
  logger "Full backup of web server completed."
  read -p -r "Press any key to continue."
}
fixperms () {
# Searches the web root for permission problems, and if found, fixes them.
  confirmcommand "scan and fix permission/ownership issues in ${webdir}?"
  find ${webdir}/*/html -type d -exec chmod a+rx {} +
  find ${webdir}/*/html -type f -exec chmod a+r {} +
  chown -R ${webuser} ${webdir}/*/html
  echo "All permissions and ownership has been fixed."
  logger "Fixed all ownership and permissions issues."
  read -p -r "Press any key to continue."
}
anti () {
# Enables some basic anti DoS measures on the host.
confirmcommand "Harden the Linux Kernel Against DDoS Attacks"
echo "kernel.printk = 4 4 1 7
kernel.panic = 10 
kernel.sysrq = 0 
kernel.shmmax = 4294967296 
kernel.shmall = 4194304 
kernel.core_uses_pid = 1 
kernel.msgmnb = 65536 
kernel.msgmax = 65536 
vm.swappiness = 20 
vm.dirty_ratio = 80 
vm.dirty_background_ratio = 5 
fs.file-max = 2097152 
net.core.netdev_max_backlog = 262144 
net.core.rmem_default = 31457280 
net.core.rmem_max = 67108864 
net.core.wmem_default = 31457280 
net.core.wmem_max = 67108864 
net.core.somaxconn = 65535 
net.core.optmem_max = 25165824 
net.ipv4.neigh.default.gc_thresh1 = 4096 
net.ipv4.neigh.default.gc_thresh2 = 8192 
net.ipv4.neigh.default.gc_thresh3 = 16384 
net.ipv4.neigh.default.gc_interval = 5 
net.ipv4.neigh.default.gc_stale_time = 120 
net.netfilter.nf_conntrack_max = 10000000 
net.netfilter.nf_conntrack_tcp_loose = 0 
net.netfilter.nf_conntrack_tcp_timeout_established = 1800 
net.netfilter.nf_conntrack_tcp_timeout_close = 10 
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10 
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 20 
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 20 
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20 
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20 
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10 
net.ipv4.tcp_slow_start_after_idle = 0 
net.ipv4.ip_local_port_range = 1024 65000 
net.ipv4.ip_no_pmtu_disc = 1 
net.ipv4.route.flush = 1 
net.ipv4.route.max_size = 8048576 
net.ipv4.icmp_echo_ignore_broadcasts = 1 
net.ipv4.icmp_ignore_bogus_error_responses = 1 
net.ipv4.tcp_congestion_control = htcp 
net.ipv4.tcp_mem = 65536 131072 262144 
net.ipv4.udp_mem = 65536 131072 262144 
net.ipv4.tcp_rmem = 4096 87380 33554432 
net.ipv4.udp_rmem_min = 16384 
net.ipv4.tcp_wmem = 4096 87380 33554432 
net.ipv4.udp_wmem_min = 16384 
net.ipv4.tcp_max_tw_buckets = 1440000 
net.ipv4.tcp_tw_recycle = 0 
net.ipv4.tcp_tw_reuse = 1 
net.ipv4.tcp_max_orphans = 400000 
net.ipv4.tcp_window_scaling = 1 
net.ipv4.tcp_rfc1337 = 1 
net.ipv4.tcp_syncookies = 1 
net.ipv4.tcp_synack_retries = 1 
net.ipv4.tcp_syn_retries = 2 
net.ipv4.tcp_max_syn_backlog = 16384 
net.ipv4.tcp_timestamps = 1 
net.ipv4.tcp_sack = 1 
net.ipv4.tcp_fack = 1 
net.ipv4.tcp_ecn = 2 
net.ipv4.tcp_fin_timeout = 10 
net.ipv4.tcp_keepalive_time = 600 
net.ipv4.tcp_keepalive_intvl = 60 
net.ipv4.tcp_keepalive_probes = 10 
net.ipv4.tcp_no_metrics_save = 1 
net.ipv4.ip_forward = 0 
net.ipv4.conf.all.accept_redirects = 0 
net.ipv4.conf.all.send_redirects = 0 
net.ipv4.conf.all.accept_source_route = 0 
net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
sysctl -p
apt install iptables-persistent -y
### 1: Drop invalid packets ### 
/sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP  
### 2: Drop TCP packets that are new and are not SYN ### 
/sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP  
### 3: Drop SYN packets with suspicious MSS value ### 
/sbin/iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  
### 4: Block packets with bogus TCP flags ### 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
/sbin/iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP  
### 5: Block spoofed packets ###
# This command will disable the ability to connect to the node from a local network.
#/sbin/iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
#/sbin/iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP  
### 6: Drop ICMP (you usually don't need this protocol) ### 
/sbin/iptables -t mangle -A PREROUTING -p icmp -j DROP  
### 7: Drop fragments in all chains ### 
/sbin/iptables -t mangle -A PREROUTING -f -j DROP  
### 8: Limit connections per source IP ### 
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  
### 9: Limit RST packets ### 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  
### 10: Limit new TCP connections per second per source IP ### 
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  
### 11: Use SYNPROXY on all ports (disables connection limiting rule) ### 
### Protection against port scanning ### 
/sbin/iptables -N port-scanning 
/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
/sbin/iptables -A port-scanning -j DROP
# Hidden - unlock content above in "Mitigating SYN Floods With SYNPROXY" section
iptables-save > /etc/iptables/rules.v4
iptables-save > /etc/iptables/rules.v6
echo -e "Hardened linux kernel against DDoS Attacks."
logger "Hardened linux kernel against DDoS Attacks."
read -p -r "Press any key to continue."
}
fail2ban () {
  f2bfdir=/etc/fail2ban/filter.d
  f2bdir=/etc/fail2ban
  echo
  echo -e "Depending on your focus, WebMan can apply Fail2ban in 3 different ways.\n1. nGinx\n2. Apache\n3. SSH Only\n"
  read -r version
  case $version in
  1)apt install fail2ban -y
    echo -e "[Definition]\nfailregex = ^<HOST> -.*GET .*/~.*\nignoreregex =" > ${f2bfdir}/nginx-nohome.conf && echo -e "[Definition]\nfailregex = ^<HOST> -.*GET http.*\nignoreregex =" > ${f2bfdir}/nginx-noproxy.conf && cp ${f2bfdir}/apache-badbots.conf ${f2bfdir}/nginx-badbots.conf
    echo -e "[sshd]\nenabled = true\nport = 22\nlogpath = %(sshd_log)s\n\n[sshd-ddos]\nenabled = true\nport = 22\nlogpath = %(sshd_log)s\n\n[recidive]\nenabled = true\nbantime = -1 ; Indefinitely\nfindtime = 1d\n\n[nginx-nohome]\nenabled  = true\nport = http,https\nfilter = nginx-nohome\nlogpath = /var/log/nginx/access.log\nmaxretry = 2\n\n[nginx-noproxy]\nenabled = true\nport = http,https\nfilter = nginx-noproxy\nlogpath = /var/log/nginx/access.log\nmaxretry = 2\n\n[nginx-badbots]\nenabled  = true\nport = http,https\nfilter = nginx-badbots\nlogpath = /var/log/nginx/access.log\nmaxretry = 2\n\n[nginx-http-auth]\nenabled = true\nfilter = nginx-http-auth\nport = http,https" > ${f2bdir}/jail.local
    service fail2ban restart;;
  2)apt install fail2ban -y
    echo -e "[sshd]\nenabled = true\nport = 22\nlogpath = %(sshd_log)s\n\n[sshd-ddos]\nenabled = true\nport = 22\nlogpath = %(sshd_log)s\n\n[recidive]\nenabled = true\nbantime = -1 ; Indefinitely\nfindtime = 1d\n\n[apache]\nenabled = true\nport = http,https\n\n[apache-overflows]\nenabled = true\nport = http,https\n\n[apache-badbots]\nenabled = true\nport = http,https" > ${f2bdir}/jail.local
    service fail2ban restart;;
  3)apt install fail2ban -y
    echo -e "[sshd]\nenabled = true\nport = 22\nlogpath = %(sshd_log)s\n\n[sshd-ddos]\nenabled = true\nport = 22\nlogpath = %(sshd_log)s\n\n[recidive]\nenabled = true\nbantime = -1 ; Indefinitely\nfindtime = 1d" > ${f2bdir}/jail.local
    service fail2ban restart;;
  esac
  logger "Installed and set up Fail2ban Jails."
  read -p -r "Press any key to continue."
}
honey () {
  confirmcommand "install the Modern Honey Network (MHN) onto this server?"
  git clone https://github.com/threatstream/mhn.git
  ./mhn/install.sh
  echo -e "Installed Modern Honey Network. Please see https://github.com/threatstream/mhn.\n"
  logger "Installed Modern Honey Network."
  read -p -r "Press any key to continue."
}
sslkeygen () {
# Creates self-signed SSL certificates and Diffie Helman Parameters.
  if [ ! -d ${ssldir} ]; then
  mkdir -p ${ssldir}
  fi

  if [ -z "$1" ]; then
  echo -e "You must specify a name for the SSL certificate."
  read -p -r "Press any key to continue."
  else
  confirmcommand "Create a new SSL certificate for $HOSTNAME (Self-Signed)"
  openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout "${ssldir}/$1.key" -out "${ssldir}/$1.crt"
  echo "Created SSL certificates in ${ssldir}/${arg1}"
  logger "Created SSL certificates in ${ssldir}/${arg1}"
  fi
  checkdiffie
}
checkdiffie () {
  # Check if DH parameters exist, and if not, prompt to create them.
  if [ ! -f "${ssldir}"/dhparam.pem ]; then
  echo -e "No Diffie Helman Parameters found.\n"
  echo -e "DH Parameters are Required for SSL Perfect Forware Secrecy.\n"
  confirmcommand "Create Diffie Helman Parameters for ${HOSTNAME}"
  openssl dhparam -out ${ssldir}/dhparam.pem 4096
  # Creates nGinx snippet for Self-Signed SSL.
  printf "ssl_certificate %s/%s.crt;\nssl_certificate_key %s/%s.key;\nssl_dhparam %s/dhparam.pem;\n" "${ssldir}" "${arg1}" "${ssldir}" "${arg1}" "${ssldir}" >> /etc/nginx/snippets/self-signed-"${arg1}".conf
  else
  printf "ssl_certificate %s/%s.crt;\nssl_certificate_key %s/%s.key;\nssl_dhparam %s/dhparam.pem;\n" "${ssldir}" "${arg1}" "${ssldir}" "${arg1}" "${ssldir}" >> /etc/nginx/snippets/self-signed-"${arg1}".conf
  fi
  if [ ! -f "${ssldir}"/dhparam.pem ]; then
  echo "Diffie Helman Parameters already exist."
  confirmcommand "Generate new Diffie Helman Parameters for ${HOSTNAME}"
  openssl dhparam -out ${ssldir}/dhparam.pem 4096
  echo "Created new Diffie Helman Parameters for $HOSTNAME"
  logger "Created new Diffie Helman Parameters for $HOSTNAME"
  read -p -r "Press any key to continue."
  fi
}
menu0 () {
  echo ' #######################################################################'
  echo ' ##                                                                   ##'
  echo ' ##  1. Maintenance                                                   ##'
  echo ' ##  2. Security                                                      ##'
  echo ' ##  3. Setup                                                         ##'
  echo ' ##                                                                   ##'
  echo ' #######################################################################'
}
menu1 () {
  echo ' #######################################################################'
  echo ' ##  fixperms - Fixes common web permissions issues.                  ##'
  echo ' ##  backup <save_as> <dir_to_backup> - Directory Backup              ##'
  echo ' ##  backup-full - Full webserver backup                              ##'
  echo ' ##  rws - Restarts Web Services                                      ##'
  echo ' ##  rlws - Reloads all web services                                  ##'
  echo ' ##  home - Back to main menu.                                        ##'
  echo ' #######################################################################'
}
menu2 () {
  echo ' #######################################################################'
  echo ' ##  sslkeygen <certificate_name> - Self-Signed SSL & DH Parameters   ##'
  echo ' ##  diffie - Checks and Generates Diffie Hellman Parameters          ##'
  echo ' ##  anti - Enables Simple Anti DDoS Measures                         ##'
  echo ' ##  honey - Installs MHN (Modern Honey Network)                      ##'
  echo ' ##  fail2ban - Installs and configures fail2ban jails                ##'
  echo ' ##  home - Back to main menu.                                        ##'
  echo ' #######################################################################'
}
menu3 () {
  echo ' #######################################################################'
  echo ' ##  wordpress - Download latest wordpress version.                   ##'
  echo ' ##  nextcloud - Download latest nextcloud version.                   ##'
  echo ' ##  netdata - Builds & Installs latest NetData Monitoring System     ##'
  echo ' ##  letsencrypt - LE Manager for installing, issuing and renewing    ##'
  echo ' ##  home - Back to main menu.                                        ##'
  echo ' #######################################################################'
}
head () {
  clear
  echo -e '\n'
  echo -e '         ██╗    ██╗███████╗██████╗ ███╗   ███╗ █████╗ ███╗   ██╗        '
  echo -e '         ██║    ██║██╔════╝██╔══██╗████╗ ████║██╔══██╗████╗  ██║        '
  echo -e '         ██║ █╗ ██║█████╗  ██████╔╝██╔████╔██║███████║██╔██╗ ██║        '
  echo -e '         ██║███╗██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══██║██║╚██╗██║        '
  echo -e '         ╚███╔███╔╝███████╗██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║        '
  echo -e '          ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝        '
  echo -e ' #######################################################################'
  echo -e ' #######################################################################'
  echo -e ' ##   This script was made to automate repetitive maintenence tasks.  ##'
  echo -e ' ##     Do not use this script unless you know what you are doing.    ##'
  echo -e ' #######################################################################\n'
  ${mid}
}
if [ -z "${mid}" ]; then
mid=menu0
fi
while :
  do
    head
    read -r cmnd arg1 arg2
    case $cmnd in
	  1) mid=menu1;;
	  2) mid=menu2;;
	  3) mid=menu3;;
	  anti) anti;;
      backup) backup "${arg1}" "${arg2}";;
	  backup-full) bws;;
	  diffie) checkdiffie;;
	  fixperms) fixperms;;
	  fail2ban) fail2ban;;
	  home) mid=menu0;;
	  honey) honey;;
	  letsencrypt) letsencrypt;;
	  nextcloud) nextcloud;;
      netdata) netdata;;
      rws) rws;;
      rlws) rlws;;
	  sslkeygen) sslkeygen "${arg1}";;
      wordpress) wordpress;;
      *) echo -e '\nI'\'m not sure I got that. Come Again'\?' && sleep 2;;
    esac
done