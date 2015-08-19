# Copyright 2013 Zhipeng Li
#
# This file is part of SDN application: Traffic Engineering.
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
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
Turns your complex OpenFlow switches into load balance capability.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ipv4

from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class sdn_traffic (object):
  """
  Waits for OpenFlow switches to connect and makes them traffic engineering capable.
  """
  traffic_count = 0
  def __init__ (self):
    core.openflow.addListeners(self)
    #core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
    #self.transparent = transparent
  
  def _handle_ConnectionUp (self, event):
    self.traffic_count = 0
    msg = of.ofp_flow_mod()
    msg.cookie = 0
    msg.command = of.OFPFC_ADD
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.priority = of.OFP_DEFAULT_PRIORITY
    msg._buffer_id = of.NO_BUFFER
    msg.out_port = of.OFPP_NONE
    msg.flags = 0
    msg.match.dl_type = 0x0800
    msg.match.nw_proto = 17 #udp
    msg.match.nw_dst = IPAddr("192.168.3.100")
    msg.actions.append(of.ofp_action_output(port = 3))
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    event.connection.send(msg)
    
    msg = of.ofp_flow_mod()
    msg.cookie = 0
    msg.command = of.OFPFC_ADD
    msg.idle_timeout = 0
    msg.hard_timeout = 0
    msg.priority = of.OFP_DEFAULT_PRIORITY
    msg._buffer_id = of.NO_BUFFER
    msg.out_port = of.OFPP_NONE
    msg.flags = 0
    msg.match.dl_type = 0x0800
    #msg.match.nw_proto = 17 #udp
    msg.match.in_port = 4
    msg.match.nw_dst = IPAddr("192.168.13.3")
    msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("00:24:E8:3C:3B:80")))
    msg.actions.append(of.ofp_action_output(port = 3))
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    event.connection.send(msg)
    log.info("Path of openflow switch %s: initialing", dpidToStr(event.dpid))

  def _handle_PacketIn(self, event):
    if event.port != 3:
      return
    self.traffic_count += 1
    log.info("icmp packet inport:3, count: %d", self.traffic_count)
    packet = event.parsed
    if(self.traffic_count == 32):
    #if(packet.type == packet.IP_TYPE): # 0x0800
      #ip = packet.find('ipv4')
      #if ip is None:
       # log.info("This packet isn't IP!")
        #return
      #if ip.protocol == ip.UDP_PROTOCOL and ip.dstip == IPAddr("192.168.4.100"):
        msg = of.ofp_flow_mod()
        msg.cookie = 0
        msg.command = of.OFPFC_MODIFY
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.priority = of.OFP_DEFAULT_PRIORITY
        msg._buffer_id = of.NO_BUFFER
        msg.out_port = of.OFPP_NONE
        msg.flags = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_proto = 17 #udp
        msg.match.nw_dst = IPAddr("192.168.3.100")
        msg.actions.append(of.ofp_action_output(port = 1))
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        #log.info("Path of openflow switch %s: initialing", dpidToStr(event.dpid))

def launch ():
  #def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an sdn Traffic Engineering application.
  """

  core.registerNew(sdn_traffic)
  #core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  #core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  log.info("Traffic Engineering component is running!")
  log.info("Waiting for oSwitch1 connection up event...")
