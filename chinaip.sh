#!/bin/sh
#wget http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
IPLIST_FILE=/etc/chinaip.txt
PROC_FILE=/proc/net/ddos_chinaip_input
while read line; do
	ipstr=`echo $line|awk -F'|' '{print $4 "," $5}'`
	echo $ipstr > $PROC_FILE
done < $IPLIST_FILE
