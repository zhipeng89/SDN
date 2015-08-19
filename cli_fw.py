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
Turns your complex OpenFlow switches into stupid hubs.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

log = core.getLogger()

class FireWallCLI (object):
  def __init__(self):
    log.debug("Initializing firewall CLI")

  def cmd(self):
    log.debug("Add, Delete or Show?-->")
    self.cmd_s = raw_input("Add, Delete or Show?-->")
  

def launch ():
  log.info("FireWall CLI running.")
  FwCli = FireWallCLI()
  core.Interactive.variables['FwCli'] = FwCli
  
