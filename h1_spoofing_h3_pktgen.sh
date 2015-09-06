#! /bin/bash
    "fanout - number of child switch per parent switch"

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
  echo "Adding h1-eth0"
 pgset "add_device h1-eth0" 
  echo "Setting max_before_softirq 1"
 pgset "max_before_softirq 1"


# device config
# ipg is inter packet gap. 0 means maximum speed.

CLONE_SKB="clone_skb 0"
# NIC adds 4 bytes CRC
PKT_SIZE="pkt_size 10"

# COUNT 0 means forever
#COUNT="count 0"
COUNT="count 10"
IPG="ipg 0"

PGDEV=/proc/net/pktgen/h1-eth0
  echo "Configuring $PGDEV"
 pgset "$COUNT"
 pgset "$CLONE_SKB"
 pgset "$PKT_SIZE"
#pgset "$IPG"
 pgset "src_mac 00:00:00:00:00:03"  # ip spoofing
 pgset "src_min 10.0.0.3"
 pgset "dst 10.0.0.2"
 pgset "dst_mac 00:00:00:00:00:02"
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
