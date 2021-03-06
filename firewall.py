# Copyright 2015 Zhipeng Li
#
# This file is a SDN application: FireWall.
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
Turns your complex OpenFlow switches into firewall capability.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ipv4

from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr

from cmd_fw import cmd_fw
from cmd_fw import CmdStarted

from pox.lib.recoco import Timer

log = core.getLogger()

class sdn_firewall (object):
  """
  Waits for OpenFlow switches to connect and makes them firewall capable.
  """
  traffic_count = 0
  def __init__ (self):
    self.recurring = True
    core.openflow.addListeners(self)
    #core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
    #self.transparent = transparent
  
  def _handle_ConnectionUp (self, event):    
    log.debug("%s connection up, FireWall APP install complete!", dpidToStr(event.dpid))
    #cmd_fw.raiseEvent(CmdStarted)
    #self.timer = Timer(3, cmd_fw.raiseEvent, recurring = True, args=[CmdStarted(event.connection, event.ofp)])
    #log.info("%s FireWall initialing complete!", dpidToStr(event.dpid))
    #while(True):
      #s = raw_input('Add, Delete or Show?-->')
  
  def _handle_ConnectionDown (self, event):    
    #self.timer.cancel()
    log.debug("%s connection down, FireWall APP uninstall complete!", dpidToStr(event.dpid))

  #def _handle_PacketIn(self, event):
    #log.info("Path of openflow switch %s: initialing", dpidToStr(event.dpid))
  #@property
  def login(self):
    log.debug("FireWall login-->")
    passwd = raw_input('Input passwd-->')
    print passwd

def launch ():
  core.registerNew(sdn_firewall)
  #core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  #core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  log.info("FireWall component is running!")
  log.info("Waiting for OpenVSwitch connection up event...")
  #cli = sdn_firewall()
  core.Interactive.variables['cli'] = core.sdn_firewall
