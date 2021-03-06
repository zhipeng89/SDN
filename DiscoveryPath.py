#!/usr/bin/python
#-*- coding: UTF-8 -*-
from pox.core import core
from pox.lib.util import dpid_to_str,str_to_dpid
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.recoco import Timer
import pox.lib.packet as pkt
import time

Switch_set = {}          #Switch_set的格式为{dpid1:[(dpid2,port1,port2),...],}
Link_set = []            #Link_set的格式为[(dpid1,dpid2),..]
Hosts = {}              #Hosts1的格式为{h1:(s1,port1), h2:...,s2...}



log = core.getLogger()

class DiscoveryPath(EventMixin):
	def __init__(self):
		log.info("DiscoveryPath has come up")
		def startup():
			core.openflow.addListeners(self)
			core.openflow_discovery.addListeners(self)
			core.host_tracker.addListeners(self)
		core.call_when_ready(startup, ('openflow','openflow_discovery','host_tracker'))

	def _handle_LinkEvent(self,event):
		global Switch_set
		global Link_set
		dpid1 = dpid_to_str(event.link.dpid1)  #OpenFlow 交换机 1 的 dpid
		dpid2 = dpid_to_str(event.link.dpid2)  #OpenFlow 交换机 2 的 dpid
		port1 = event.link.port1  #OpenFlow 交换机 1 通过端口 port1连接到该链路上
		port2 = event.link.port2  #OpenFlow 交换机 2 通过端口 port2连接到该链路上
		if event.added == True:
			# 更新 Switch_set
			if dpid1 not in Switch_set:
				Switch_set[dpid1] = []
				Switch_set[dpid1].append((dpid2,port1,port2))

			elif (dpid2,port1,port2) not in Switch_set[dpid1]:
				Switch_set[dpid1].append((dpid2,port1,port2))

			else:
				pass

			if dpid2 not in Switch_set:
				Switch_set[dpid2] = []
				Switch_set[dpid2].append((dpid1,port2,port1))

			elif (dpid1,port2,port1) not in Switch_set[dpid2]:
				Switch_set[dpid2].append((dpid1,port2,port1))

			else:
				pass

			# 更新 Link_set
			if (dpid1, dpid2) not in Link_set and (dpid2, dpid1) not in Link_set:
				Link_set.append((dpid1, dpid2))

		elif event.removed == True:
			# 更新 Switch_set
			if dpid1 not in Switch_set:
				pass

			elif not Switch_set[dpid1]:
				del Switch_set[dpid1]

			elif (dpid2,port1,port2) in Switch_set[dpid1]:
				Switch_set[dpid1].remove((dpid2,port1,port2))

			else:
				pass

			if dpid2 not in Switch_set:
				pass

			elif not Switch_set[dpid2]:
				del Switch_set[dpid2]

			elif (dpid1,port2,port1) in Switch_set[dpid2]:
				Switch_set[dpid2].remove((dpid1,port2,port1))

			else:
				pass

			# 更新　Link_set
			if (dpid1, dpid2) in Link_set or (dpid2, dpid1) in Link_set:
				if (dpid1, dpid2) in Link_set:
					Link_set.remove((dpid1,dpid2))

				elif (dpid2, dpid1) in Link_set:
					Link_set.remove((dpid2,dpid1)) 

		else:
			pass
		#print "Switch_set:",Switch_set
		#print "Link_set:",Link_set


	def _handle_ConnectionUp(self,event):
		global Switch_set
		dpid=dpid_to_str(event.dpid)
		if dpid not in Switch_set:
			Switch_set[dpid] = []
		#log.info("Switch %s has come up.",dpid)
		#print "Switch_set:",Switch_set

	def _handle_ConnectionDown(self,event):
		global Switch_set
		dpid=dpid_to_str(event.dpid)
		if dpid in Switch_set:
			del Switch_set[dpid]
		#log.info("Switch %s has shutdown.",dpid)
		#print "Switch_set:",Switch_set

	def _handle_HostEvent(self, event):
		global Hosts
		mac=str(event.entry.macaddr)
		to_switch=dpid_to_str(event.entry.dpid)
		port = event.entry.port
		if event.join == True:
			if mac not in Hosts:
				Hosts[mac] = (to_switch,port)

			elif (to_switch,port) not in Hosts[mac]:
				Hosts[mac] = (to_switch,port)

			else:
				pass
			log.info("host %s has come up.",mac)

		elif event.leave == True:
			if mac not in Hosts:
				pass

			else:
				del Hosts[mac]
		else:
			pass
		#log.info("host %s has shutdown.",mac)
		#print "Hosts:",Hosts



def launch():
	core.registerNew(DiscoveryPath)






