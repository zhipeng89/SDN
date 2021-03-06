# Copyright 2015 Zhipeng Li
#
# This file is a SDN application: Source Address Verification.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
import csv


log = core.getLogger()
#policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]

''' Add your global variables here ... '''



class SrcAddrVerify (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):
        ''' Add your logic here ... '''
        #global policyFile
        #log.debug("installed on %s", dpidToStr(event.dpid))
        log.debug("Connection %s" % (event.connection,))
        #print dpidToStr(event.dpid)
        if event.dpid == 2:
          # s2
          msg = of.ofp_flow_mod()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          event.connection.send(msg)
        elif event.dpid == 1:
          # s1
          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.dl_src = EthAddr("00:00:00:00:00:01")
          msg.match.dl_type = 0x0800
          msg.match.nw_src = IPAddr("10.0.0.1")
          #msg.match.nw_src = IPAddr("192.168.0.1")
          msg.actions.append(of.ofp_action_output(port = 2))
          event.connection.send(msg)

          #arp
          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.dl_src = EthAddr("00:00:00:00:00:01")
          msg.match.dl_type = 0x0806
          msg.match.nw_src = IPAddr("10.0.0.1")
          #msg.match.nw_src = IPAddr("192.168.0.1")
          msg.actions.append(of.ofp_action_output(port = 2))
          event.connection.send(msg)

          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.match.dl_type = 0x0806
          msg.match.nw_dst = IPAddr("10.0.0.1")
          msg.actions.append(of.ofp_action_output(port = 1))
          #msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:01")))
          event.connection.send(msg)
        elif event.dpid == 3:
          # s3
          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.dl_src = EthAddr("00:00:00:00:00:03")
          msg.match.dl_type = 0x0800
          msg.match.nw_src = IPAddr("10.0.0.3")
          #msg.match.nw_src = IPAddr("10.0.0.1")
          msg.actions.append(of.ofp_action_output(port = 2))
          event.connection.send(msg)

          #arp
          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.dl_src = EthAddr("00:00:00:00:00:03")
          msg.match.dl_type = 0x0806
          msg.match.nw_src = IPAddr("10.0.0.3")
          msg.actions.append(of.ofp_action_output(port = 2))
          event.connection.send(msg)

          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.match.dl_type = 0x0806
          msg.match.nw_dst = IPAddr("10.0.0.3")
          msg.actions.append(of.ofp_action_output(port = 1))
          #msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:02")))
          event.connection.send(msg)
        elif event.dpid == 4:
          # s4
          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.dl_src = EthAddr("00:00:00:00:00:02")
          msg.match.dl_type = 0x0800
          msg.match.nw_src = IPAddr("10.0.0.2")
          #msg.match.nw_src = IPAddr("172.16.0.1")
          msg.actions.append(of.ofp_action_output(port = 2))
          event.connection.send(msg)

          #arp
          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.dl_src = EthAddr("00:00:00:00:00:02")
          msg.match.dl_type = 0x0806
          msg.match.nw_src = IPAddr("10.0.0.2")
          msg.actions.append(of.ofp_action_output(port = 2))
          event.connection.send(msg)

          msg = of.ofp_flow_mod()
          msg.priority = 42
          msg.in_port = 1
          msg.match.dl_type = 0x0806
          msg.match.nw_dst = IPAddr("10.0.0.2")
          msg.actions.append(of.ofp_action_output(port = 1))
          #msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:02")))
          event.connection.send(msg)

    def _handle_PacketIn(self, event):
      if event.dpid == 1:
        # s1
        msg = of.ofp_flow_mod()
        msg.priority = 42
        #msg.in_port = 1
        #msg.dl_src = EthAddr("00:00:00:00:00:01")
        msg.match.dl_type = 0x0800   #ipv4
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:01")))
        event.connection.send(msg)
      elif event.dpid == 3:
        # s3
        msg = of.ofp_flow_mod()
        msg.priority = 42
        #msg.in_port = 1
        #msg.dl_src = EthAddr("00:00:00:00:00:01")
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 1))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:03")))
        event.connection.send(msg)
      elif event.dpid == 4:
        # s4
        msg = of.ofp_flow_mod()
        msg.priority = 42
        #msg.in_port = 1
        #msg.dl_src = EthAddr("00:00:00:00:00:02")
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 1))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:02")))
        event.connection.send(msg)

    def _handle_PortStatus(self, event):
      if event.added:
        action = "added"
      elif event.deleted:
        action = "deleted"
      else:
        action = "modified"
      print "Port %s on Switch %s has been %s." %(event.port, event.dpid, action)

    def _handle_HostEvent(self, event):
      log.debug("Host event!!!!!!")
      if event.join == True:
        print "Ture"

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(SrcAddrVerify)
