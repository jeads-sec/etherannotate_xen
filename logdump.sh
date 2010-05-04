#!/bin/bash

rm ./xenlog.log

while true;
do
	sudo xm dmesg -c >> ./xenlog.log
done;
