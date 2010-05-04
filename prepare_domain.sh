#!/bin/bash


#reserve 1Gb for domain 0
DOM0MEM=2048


 
if [ "$1" = "" ];
then
	echo "Please specify a domain"
	exit
fi

if [ "$1" = "0" ];
then
	echo "This script should not be run on domain 0"
	exit
fi

DOM_MEM=`sudo xm list | tr -s "[:space:]" | cut --fields=2,3 -d ' ' | grep "^$1\\b"`
DOM=$1
MEM=`echo "$DOM_MEM" | cut -d ' ' -f 2`

if [ "$MEM" = "" ];
then
	echo "Could not obtain current amount of memory allocated to domain $DOM"
	exit
fi

echo "Changing amount of memory reserved for dom0 to $DOM0MEM"
sudo xm mem-set 0 $DOM0MEM

NEWMEM=`expr $MEM + 256`

echo Changing maximum allocation for domain $DOM from $MEM to $NEWMEM
sudo xm mem-max $DOM $NEWMEM

