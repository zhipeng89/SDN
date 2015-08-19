#! /bin/bash

#modprobe pktgen


function pgset() {
    local result

    echo $1 > $PGDEV

    result=`cat $PGDEV | fgrep "Result: OK:"`
    if [ "$result" = "" ]; then
         cat $PGDEV | fgrep Result:
    fi
}

function pg() {
    echo inject > $PGDEV
    cat $PGDEV
}

# Config Start Here -----------------------------------------------------------


# thread config
# Each CPU has own thread. Two CPU exammple. We add eth1, eth2 respectivly.

PGDEV=/proc/net/pktgen/kpktgend_0
  echo "Removing all devices"
 pgset "rem_device_all" 
  echo "Adding eth1"
 pgset "add_device eth1" 
  echo "Setting max_before_softirq 10000"
 pgset "max_before_softirq 10000"


# device config
# ipg is inter packet gap. 0 means maximum speed.

CLONE_SKB="clone_skb 1000000"
# NIC adds 4 bytes CRC
PKT_SIZE="pkt_size 1200"

# COUNT 0 means forever
#COUNT="count 0"
COUNT="count 0"
IPG="ipg 0"

PGDEV=/proc/net/pktgen/eth1
  echo "Configuring $PGDEV"
 pgset "$COUNT"
 pgset "$CLONE_SKB"
 pgset "$PKT_SIZE"
#pgset "$IPG"
 pgset "src_mac 00:0A:EB:6A:6F:0D"
 pgset "src_min 192.168.13.1"
 pgset "dst 192.168.13.3"
 pgset "dst_mac 00:24:E8:3C:3B:80"
# pgset "udp_src_min 8000"
# pgset "udp_src_max 8000"
# pgset "udp_dst_min 8000"
# pgset "udp_dst_max 8000"
 


# Time to run
PGDEV=/proc/net/pktgen/pgctrl

 echo "Running... ctrl^C to stop"
 pgset "start" 
 echo "Done"

# Result can be vieved in /proc/net/pktgen/eth1
