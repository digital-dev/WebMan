#!/bin/bash
clear
if [ $EUID -ne 0 ]; then
echo "And you are?.. (not root)"
exit 1
fi
# Includes
. "webfunk.sh"
logfile=logs/webman.log
mainscreen () {
  clear
  echo '           __      __      ___.       _____                         '
  echo '          /  \    /  \ ____\_ |__    /     \ _____    ____          '
  echo '          \   \/\/   // __ \| __ \  /  \ /  \\__  \  /    \         '
  echo '           \        /\  ___/| \_\ \/    Y    \/ __ \|   |  \        '
  echo '            \__/\  /  \___  >___  /\____|__  (____  /___|  /        '
  echo '                 \/       \/    \/         \/     \/     \/         '
  echo
  echo ' ###################################################################'
  echo ' ##       For a list of supported commands, please type "help"    ##'
  echo ' ##                    For the clever sysadmin.                   ##'
  echo ' ##                                                               ##'
  echo ' ###################################################################'
  echo
}
while :
  do
    mainscreen
    read -r cmnd arg1 arg2
    case $cmnd in
      help) help;;
      bws) bws;;
      rws) rws;;
      dwp) dwp;;
	  dnc) dnc;;
      rlws) rlws;;
      fixperms) fixperms;;
      sslkeygen) sslkeygen ${arg1};;
      backup) backup "${arg1}" "${arg2}";;
    esac
done
