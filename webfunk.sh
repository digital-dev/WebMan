#!/bin/bash
ssldir=/etc/nginx/ssl
backupdir=/var/www/backups
webdir=/var/www
webuser=www-data:www-data
if [ ! -d logs ]; then
        mkdir logs
fi
if [ ! -f "$logfile" ]; then
        touch "$logfile"
fi
help () {
  echo '#######################################################################'
  echo '##   This script was made to automate repetative maintenence tasks.  ##'
  echo '##     Do not use this script unless you know what you are doing.    ##'
  echo '#######################################################################'
  echo '##                                                                   ##'
  echo '##  fixperms - Fixes common web permissions issues.                  ##'
  echo '##  backup <save_as> <dir_to_backup> - Directory Backup              ##'
  echo '##  sslkeygen <certificate_name> - Self-Signed SSL & DH Parameters   ##'
  echo '##  backup-full - Full webserver backup                              ##'
  echo '##  rws - Restarts Web Services                                      ##'
  echo '##  rlws - Reloads all web services                                  ##'
  echo '##  wordpress - Download latest wordpress version.                   ##'
  echo '##  nextcloud - Download latest nextcloud version.                   ##'
  echo '##  netdata - Builds & Installs latest NetData Monitoring System     ##'
  echo '##  letsencrypt - Installs latest version of letsencrypt             ##'
  echo '#######################################################################'
  echo
  read -n1 -r -p "Press any key to continue..."
}


# Helps with creating a log of all actions performed.
logger () {
  echo -e "$(date +%a-%b-%d@%T): ${1}" >> "${logfile}"
}

# Helps confirm the use of a dangerous or irreversible command.
confirmcommand () {
  while :
  do
  read -r -p "Are you sure you wish to $1?" ccmnd
  case $ccmnd in
  [Yy]* ) break ;;
  [Nn]* ) exit 1;;
  * ) echo "Please enter only yes or no. (y/n)"
  esac
  done
}

# Downloads the latest version of wordpress and unpacks it.
wordpress () {
  wget https://wordpress.org/latest.tar.gz
  tar -xvf latest.tar.gz
  sudo chown -R ${webuser} wordpress/ && echo -e "Fixed Ownership.\\n"
  rm latest.tar.gz
  echo "Downloaded and extrated latest version of wordpress."
  logger "Downloaded and extracted latest version of wordpress, fixed ownership."
  sleep 3
}

# Downloads the latest version of nextcloud and unpacks it.
nextcloud () {
  wget https://download.nextcloud.com/server/releases/latest.zip
  unzip latest.zip
  chown -R ${webuser} nextcloud/ && echo -e "Fixed Ownership.\\n"
  rm latest.zip
  echo "Downloaded and extracted latest version of nextcloud."
  logger "Downloaded and extracted latest version of nextcloud."
  sleep 3
}

netdata () {
confirmcommand "Install NetData Monitoring system"
bash <(curl -Ss https://my-netdata.io/kickstart.sh) all
echo "Installed NetData monitoring system."
logger "Installed NetData monitoring system."
sleep 3
}

letsencrypt () {
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
esac
}

# Reloads all web services.
rlws () {
  service nginx reload
  service php7.0-fpm reload
  service mysql reload
  echo "Web services have been reloaded."
  logger "Web services have been reloaded."
  sleep 3
}
# Restarts all web services.
rws () {
  service nginx restart
  service php7.0-fpm restart
  service mysql restart
  echo "Web services have been restarted."
  logger "Web services have been restarted"
  sleep 3
}

# Makes a full backup of the specified directory, including subdirs.
backup () {
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
  sleep 3
  fi
  fi
}

# Creates a full backup of the webserver, including sql.
bws () {
  mysqldump -u root --all-databases | tee "alldb-backup-$(date +%a-%b-%d@%T).sql"
  backup "full-web-backup" "${webdir}"
  echo "Backup completed successfully."
  logger "Full backup of web server completed."
  sleep 5
}

# Searches the web root for permission problems, and if found, fixes them.
fixperms () {
  find ${webdir}/*/html -type d -exec chmod a+rx {} +
  find ${webdir}/*/html -type f -exec chmod a+r {} +
  chown -R ${webuser} ${webdir}/*/html
  echo "All permissions and ownership has been fixed."
  logger "Fixed all ownership and permissions issues."
  sleep 3
}

# Creates self-signed SSL certificates and Diffie Helman Parameters.
sslkeygen () {
  if [ ! -d ${ssldir} ]; then
  mkdir -p ${ssldir}
  fi

  if [ -z "$1" ]; then
  echo -e "You must specify a name for the SSL certificate."
  sleep 2
  else
  confirmcommand "Create a new SSL certificate for $HOSTNAME (Self-Signed)"
  openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout "${ssldir}/$1.key" -out "${ssldir}/$1.crt"
  echo "Created SSL certificates in ${ssldir}/${arg1}"
  logger "Created SSL certificates in ${ssldir}/${arg1}"
  fi
  # Check if DH parameters exist, and if not, prompt to create them.
  if [ ! -f "${ssldir}"/dhparam.pem ]; then
  echo -e "No Diffie Helman Parameters found.\n"
  echo -e "DH Parameters are Required for SSL Perfect Forware Secrecy.\n"
  confirmcommand "Create Diffie Helman Parameters for ${HOSTNAME}"
  openssl dhparam -out ${ssldir}/dhparam.pem 4096
  # Creates nGinx snippet for Self-Signed SSL.
  printf "
  ssl_certificate %s/%s.crt;
  ssl_certificate_key %s/%s.key;
  ssl_dhparam %s/dhparam.pem;
  " "${ssldir}" "${arg1}" "${ssldir}" "${arg1}" "${ssldir}" >> /etc/nginx/snippets/self-signed-"${arg1}".conf
  else
  printf "
  ssl_certificate %s/%s.crt;
  ssl_certificate_key %s/%s.key;
  ssl_dhparam %s/dhparam.pem;
  " "${ssldir}" "${arg1}" "${ssldir}" "${arg1}" "${ssldir}" >> /etc/nginx/snippets/self-signed-"${arg1}".conf
  fi
  if [ ! -f "${ssldir}"/dhparam.pem ]; then
  echo "Diffie Helman Parameters already exist."
  confirmcommand "Generate new Diffie Helman Parameters for ${HOSTNAME}"
  openssl dhparam -out ${ssldir}/dhparam.pem 4096
  echo "Created new Diffie Helman Parameters for $HOSTNAME"
  logger "Created new Diffie Helman Parameters for $HOSTNAME"
  sleep 2
  fi
}