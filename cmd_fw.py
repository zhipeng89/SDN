# Copyright 2015 Zhipeng Li
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Input your firewall command
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.revent import *
from pox.lib.recoco import Timer

log = core.getLogger()

class CmdStarted(Event):
  def __init__(self, connection, ofp):
    Event.__init__(self)
    self.connection = connection
    self.dpid = connection.dpid
    self.ofp = ofp
    log.debug("CmdStarted event init.")

class Cmd_FW(EventMixin):
  """
    Class modeling a firewall cmd
  """
  _eventMixin_events = set([
    CmdStarted  
  ])

cmd_fw = Cmd_FW()

class InputCmd(object):
  def __init__(self):
    log.debug("InputCmd init.")
    cmd_fw.addListeners(self)
  
  def _handle_CmdStarted(self, event):
    log.info("%s FireWall handle cmd started", dpidToStr(event.dpid))
    cmd_s = raw_input('Add, Delete or Show FireWall rules?-->')

#def test_timer():
  #log.info("test timer")

def launch ():
  #core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  log.info("FireWall cmd input running.")
  core.registerNew(InputCmd)
  #Timer(1, cmd_fw.raiseEvent, recurring = True, args=[CmdStarted])
  #global cmd_fw
  #cmd_fw = Cmd_FW()
  #while(True):
    #s = raw_input('Add, Delete or Show?-->')
  

