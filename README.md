# WebMan

If you find this useful to you, please leave a:star:! It really does help.

![WebMan](https://i.gyazo.com/321fdd0f478c767d5362cc07bd3d3103.png)

## What WebMan Does
WebMan aims to help partially or fully automate many systems services setups and maintenance tasks that come with running web hosting services. It can assist in the setup or management the following services:

fail2ban  
Modern Honey Network  
wordpress  
nextcloud  
netdata  
letsencrypt  

## Adjustable Variables

You can adjust all of the default variables readily and easily to suit your needs.

ssldir=/etc/nginx/ssl  
backupdir=/var/www/backups  
webdir=/var/www  
webuser=www-data:www-data  
logfile=logs/webman.log  

## Maintenance functions
sslkeygen <certificate_name> - Self-Signed SSL & Diffie-Helman Parameters  
letsencrypt - LE Manager (installing, issuing certificates, renewing certificates)  
backup <save_as> <dir_to_backup> - Directory Backup  
backup-full - Full webserver backup  
rws - Restarts Web Services  
rlws - Reloads all web services  
fixperms - Fixes common web permissions issues.  

## Security Functions 
anti - Enables Simple Anti DDoS Measures  
honey - Installs MHN (Modern Honey Network)  
fail2ban - Installs and configures fail2ban jails  

## Downloads and Setups
wordpress - Download latest wordpress version.  
nextcloud - Download latest nextcloud version.  
netdata - Builds & Installs latest NetData Monitoring System  
