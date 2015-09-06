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
from collections import defaultdict
import os
''' Add your imports here ... '''
#import csv


log = core.getLogger()
#policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]

''' Add your global variables here ... '''
log = core.getLogger()

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4


def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """

  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print

  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)


def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports

  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[1]:
      return False
  return True


def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]

  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))

  assert _check_path(r), "Illegal path!"

  return r


class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet

    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()

  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self

  @property
  def is_expired (self):
    return time.time() >= self.expires_at

  def notify (self, event):
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    self.path = path

class Switch (EventMixin):
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)

  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)

  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)

        from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')

        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)

      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))

    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    self._install_path(p, match.flip())


  def _handle_PacketIn (self, event):
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        self.connection.send(msg)

    packet = event.parsed

    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if oldloc is None:
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
      # ethaddr seen at different place!
      if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].dpid), oldloc[1],
                  dpid_to_str(   loc[0].dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        # Hopefully, this is a packet we're flooding because we didn't
        # know the destination, and not because it's somehow not on a
        # path that we expect it to be on.
        # If spanning_tree is running, we might check that this port is
        # on the spanning tree (it should be).
        if packet.dst in mac_map:
          # Unfortunately, we know the destination.  It's possible that
          # we learned it while it was in flight, but it's also possible
          # that something has gone wrong.
          log.warning("Packet from %s to known destination %s arrived "
                      "at %s.%i without flow", packet.src, packet.dst,
                      dpid_to_str(self.dpid), event.port)


    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        dest = mac_map[packet.dst]
        match = of.ofp_match.from_packet(packet)
        self.install_path(dest[0], dest[1], match, event)

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True

  def _handle_ConnectionDown (self, event):
    self.disconnect()

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
        # arp
        msg = of.ofp_flow_mod() 
        msg.priority = 42
        msg.match.dl_type = 0x0806 #arp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)
        log.debug("arp for %s", dpidToStr(event.dpid))

        #icmp
        #msg = of.ofp_flow_mod() 
        #msg.priority = 42
        #msg.match.dl_type = 0x0800
        #msg.match.nw_proto = 1
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        #msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        #event.connection.send(msg)
        #log.debug("icmp for %s", dpidToStr(event.dpid))


    def _handle_PacketIn(self, event):
      if event.dpid == 1:  #s1
        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

      elif event.dpid == 2: #s2
        # h1 
        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 3))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 3
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        #h2
        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 3
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 3
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 3))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 3))
        event.connection.send(msg)

        #h3
        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 3))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 3
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

      elif event.dpid == 3:  #s3
        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)
      elif event.dpid == 4: #s4
        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.1")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 1
        msg.match.nw_src = IPAddr("10.0.0.2")
        msg.match.nw_dst = IPAddr("10.0.0.3")
        msg.actions.append(of.ofp_action_output(port = 2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.3")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 43
        msg.match.dl_type = 0x0800
        msg.match.in_port = 2
        msg.match.nw_src = IPAddr("10.0.0.1")
        msg.match.nw_dst = IPAddr("10.0.0.2")
        msg.actions.append(of.ofp_action_output(port = 1))
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
