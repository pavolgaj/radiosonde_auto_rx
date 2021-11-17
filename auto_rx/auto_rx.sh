#!/bin/bash
# Radiosonde Auto-RX Script
#
# 2017-04 Mark Jessop <vk5qi@rfhead.net>
#
# NOTE: If running this from crontab, make sure to set the appropriate PATH env-vars,
# else utilities like rtl_power and rtl_fm won't be found.
#
#	WARNING - THIS IS DEPRECATED - PLEASE USE THE SYSTEMD SERVICE
#

killall rs41mod
killall rtl_fm
#killall sdrtst
#killall sondeudp
killall rtl_tcp
killall rtl_sdr
#killall node
killall screen

#echo $$; echo $BASHPID

id=`ps -ef | grep web_start | grep python | awk '{print $2}'`
if [ $id ] 
then
    kill -SIGINT $id
fi 

id=`ps -ef | grep auto_rx | grep python | awk '{print $2}'`
if [ $id ] 
then
    kill -SIGINT $id
    sleep 30
fi 

# change into appropriate directory
cd $(dirname $0)

# Clean up old files
rm log_power*.csv

# Start auto_rx process with a 3 hour timeout.
# auto_rx will exit after this time.

python3 auto_rx.py -t 300

python3 web_start.py
