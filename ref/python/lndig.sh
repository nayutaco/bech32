#!/bin/sh
dig lseed.bitcoinstats.com +short SRV > tmp.$$$
cat tmp.$$$ | cut -d " " -f 4 | sed "s/.lseed.bitcoinstats.com.//g" | xargs -L 1 ./lntest.py > node.$$$
cat tmp.$$$ | cut -d " " -f 4 | xargs -L 1 dig +short > ip.$$$
cat tmp.$$$ | cut -d " " -f 3 > port.$$$
count=1
paste -d ',' ip.$$$ port.$$$ node.$$$ | while read line
do
	ipaddr=`echo $line | cut -d "," -f 1`
	port=`echo $line | cut -d "," -f 2`
	nodeid=`echo $line | cut -d "," -f 3`
	echo ipaddr=$ipaddr > peer$count.conf
	echo port=$port >> peer$count.conf
	echo node_id=$nodeid >> peer$count.conf
	count=$((count+1))
done
rm tmp.$$$ node.$$$ ip.$$$ port.$$$
