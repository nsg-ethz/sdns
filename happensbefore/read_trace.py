#!/usr/bin/env python

import sys
import os
import json
from collections import namedtuple, defaultdict, deque, OrderedDict
import itertools
from itertools import islice
import pprint

sys.path.append(os.path.join(os.path.dirname(__file__), "pox"))
# from pox.openflow.libopenflow_01 import *

# TODO JM: Future enhancements:
#          - Add plugin for Hosts (add trace events for pings etc)
#            -> TracePacketHostResponseBegin/End
#          - Add heuristics based on time: i.e. assume that there is a HB relationship if some time has passed
#            for: * DP packets IN host <: OUT host (configurable!)
#                 * OF messages without a barrier request in between them (configurable!)
#          - Integrate commutativity rules
#          - Report races on buffers (2 unordered events, at least one is a write)
#          - Make race detection more efficient, by using the EventRacer framework
#          - Make memory locations pretty in Graphviz (e.g. rectangles instead of ovals)


#
#
# TODO JM: Assign new tag numbers on DpIn/DpOut events to prevent loops.
#
#

# From STS:
# barrier_deque has the structure: [(None, queue_1), (barrier_request_1, queue_2), ...] where...
#   - its elements have the form (barrier_in_request, next_queue_to_use)
#   - commands are always processed from the queue of the first element (i.e. barrier_deque[0][1])
#   - when a new barrier_in request is received, a new tuple is appended to barrier_deque, containing:
#   (<the just-received request>, <queue for subsequent non-barrier_in commands until all previous commands have been processed>)
#   - the very first barrier_in is None because, there is no request to respond when we first start buffering commands
#     self.barrier_deque = [(None, Queue.PriorityQueue())]



def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    @classmethod
    def keys(cls):
       return reverse
    enums['keys'] = keys
    @classmethod
    def values(cls):
       return enums
    enums['values'] = values
    return type('Enum', (), enums)

EventType = enum('TraceTagPacket',
                 'TraceUntagPacket',
                 'TraceDpPacketOutHost', 
                 'TraceDpPacketOutSwitch', 
                 'TraceDpPacketInHost', 
                 'TraceDpPacketInSwitch', 
                 'TracePacketHostResponseBegin',
                 'TracePacketHostResponseEnd',
                 'OfHandleVendorHb',
                 'TraceOfHandleFlowMod', # TODO JM: fix
                 'TraceOfHandleFlowModFromBuffer',
                 'TraceOfHandlePacketOutFromRaw',
                 'TraceOfHandlePacketOutFromBuffer',
                 'TraceOfGeneratePacketIn',
                 'TraceOfMessageToController', 
                 'TraceOfMessageFromController', 
                 'TraceFlowTableModificationBefore',  # TODO JM: fix
                 'TraceFlowTableModificationAfter',  # TODO JM: fix
                 'TraceFlowTableRuleExpiration', 
                 'TraceFlowTableRuleMatch', 
                 'TraceFlowTableRuleTouch', 
                 'TracePacketActionModificationBegin', 
                 'TracePacketActionModificationEnd', 
                 'TracePacketActionOutput', 
                 'TracePacketActionResubmit', 
                 'TracePacketBufferReadPacket', 
                 'TracePacketBufferReadError', 
                 'TracePacketBufferWritePacket',
                 'TracePacketBufferFlushPacket')

MsgType = enum(
  'HELLO',
  'ERROR',
  'ECHO_REQUEST',
  'ECHO_REPLY',
  'VENDOR',
  'FEATURES_REQUEST',
  'FEATURES_REPLY',
  'GET_CONFIG_REQUEST',
  'GET_CONFIG_REPLY',
  'SET_CONFIG',
  'PACKET_IN',
  'FLOW_REMOVED',
  'PORT_STATUS',
  'PACKET_OUT',
  'FLOW_MOD',
  'PORT_MOD',
  'STATS_REQUEST',
  'STATS_REPLY',
  'BARRIER_REQUEST',
  'BARRIER_REPLY',
  'QUEUE_GET_CONFIG_REQUEST'
  'QUEUE_GET_CONFIG_REPLY')

# MsgReason = enum(
#   'OFPR_NO_MATCH',
#   'OFPR_ACTION')

DpPacketInTypes = [EventType.TraceDpPacketInHost, EventType.TraceDpPacketInSwitch]
DpPacketOutTypes = [EventType.TraceDpPacketOutHost, EventType.TraceDpPacketOutSwitch]
PacketBufferReadTypes = [EventType.TracePacketBufferReadPacket, EventType.TracePacketBufferReadError]
PacketBufferWriteTypes = [EventType.TracePacketBufferWritePacket, EventType.TracePacketBufferFlushPacket]

# helper, used 3 times in dict below
internal_switch_predecessor_types = [# external calls
                                     EventType.TraceFlowTableRuleTouch,
                                     EventType.TraceOfHandlePacketOutFromRaw,
                                     EventType.TracePacketBufferReadPacket,
                                     # internal 
                                     EventType.TracePacketActionModificationEnd,
                                     # internal calls
                                     EventType.TraceDpPacketOutSwitch,
                                     EventType.TraceOfMessageToController # (packet_in)
                                     ]
# mapping of events -> possible predecessor types.
predecessor_types = {
    EventType.TraceTagPacket:                [], # (special case, handled separately)
                                                      # is not added to happens-before graph
    EventType.TraceUntagPacket:              [], # (special case, handled separately)
                                                      # is not added to happens-before graph
    
    EventType.TraceDpPacketOutHost:               [EventType.TracePacketHostResponseEnd], # tag
    EventType.TraceDpPacketOutSwitch:             [EventType.TracePacketActionOutput], # tag
    
    EventType.TraceDpPacketInHost:                [EventType.TraceDpPacketOutHost, #  tag
                                                   EventType.TraceDpPacketOutSwitch], # tag
    EventType.TraceDpPacketInSwitch:              [EventType.TracePacketActionResubmit, # tag
                                                   EventType.TracePacketActionOutput, # tag
                                                   EventType.TraceDpPacketOutHost,  # tag (or topology)
                                                   EventType.TraceDpPacketOutSwitch], # tag (or topology)

    EventType.TracePacketHostResponseBegin:       [EventType.TraceDpPacketInHost], # tag
    EventType.TracePacketHostResponseEnd:         [EventType.TracePacketHostResponseBegin], # precursor_id
    
    EventType.OfHandleVendorHb:           [], # (special case, handled separately)
                                                      # generated for types packet_in, packet_out, barrier_request, flow_mod
                                                      # is not added to happens-before graph
    
    EventType.TraceOfHandleFlowModFromBuffer:     [EventType.TraceFlowTableModification], # msg
    EventType.TraceOfHandlePacketOutFromRaw:      [EventType.TraceOfMessageFromController], # msg
    EventType.TraceOfHandlePacketOutFromBuffer:   [EventType.TraceOfMessageFromController], # msg
    
    EventType.TraceOfGeneratePacketIn:            [EventType.TracePacketBufferWritePacket], # tag
    EventType.TraceOfMessageToController:         [EventType.TraceOfGeneratePacketIn], # msg
    EventType.TraceOfMessageFromController:       [EventType.TraceOfMessageToController], # as determined by OfHandleVendorHb
    
    EventType.TraceFlowTableModification:         [EventType.TraceOfMessageFromController], # msg
    EventType.TraceFlowTableRuleExpiration:  [], # (unused)
    EventType.TraceFlowTableRuleMatch:                [EventType.TraceDpPacketInSwitch], # tag
    EventType.TraceFlowTableRuleTouch:                [EventType.TraceFlowTableRuleMatch], # tag
    
    EventType.TracePacketActionModificationBegin: internal_switch_predecessor_types, # tag
    EventType.TracePacketActionModificationEnd:   [EventType.TracePacketActionModificationBegin], # precursor_id
    EventType.TracePacketActionOutput:            internal_switch_predecessor_types, # tag
    EventType.TracePacketActionResubmit:          internal_switch_predecessor_types, # tag
    
    # For packet buffers: no edges between read/writes on same switch, as that would circumvent the controller
    EventType.TracePacketBufferReadPacket:        [EventType.TraceOfHandleFlowModFromBuffer, # dpid+buffer_id
                                                   EventType.TraceOfHandlePacketOutFromBuffer], # dpid+buffer_id
    EventType.TracePacketBufferReadError:             [EventType.TraceOfHandleFlowModFromBuffer, # dpid+buffer_id
                                                   EventType.TraceOfHandlePacketOutFromBuffer], # dpid+buffer_id
    
    EventType.TracePacketBufferWritePacket:       [EventType.TraceDpPacketInSwitch, # tag
                                                   EventType.TracePacketActionOutput], # tag
    EventType.TracePacketBufferFlushPacket:       internal_switch_predecessor_types # tag
}


class HappensBeforeGraph(object):
  def __init__(self):
    self.events = []
    self.events_by_id = dict()
    self.predecessors = defaultdict(set)
    self.successors = defaultdict(set)
  
  def load_trace(self, filename):
    self.events = []
    self.events_by_id = dict()
    with open(filename) as f:
      for line in f:
        if len(line) > 0 and not line.startswith('#'):
          
          def lists_to_tuples(dct):
            '''
            Convert all lists to tuples so that the resulting objects are 
            hashable later on.
            '''
            for k,v in dct.copy().iteritems():
              if isinstance(v, list):
                dct[k] = tuple(v)
            return dct
          
          event_json = json.loads(line, object_hook=lists_to_tuples)
          event_typestr = event_json['type']
          
          assert event_typestr in EventType.values()
          event_json['type'] = EventType.values()[event_typestr]
          if 'msg_type' in event_json:
            short_type = event_json['msg_type'][5:]
            event_json['msg_type'] = MsgType.values()[short_type]
            
#           if 'msg_reason' in event_json:
#             event_json['msg_reason'] = MsgReason.values()[event_json['msg_reason']]
          
          event = namedtuple('Event', event_json)(**event_json)
          self.events.append(event)
          assert event.id not in self.events_by_id
          self.events_by_id[event.id] = event
    print "Read in " + str(len(self.events)) + " events." 
    self.events.sort(key=lambda i: i.id)
    
  
  def evaluate_rules(self):
    """
    Each rule evaluates the current event against previous events, and adds
    edges to all events that happened-before the current event.
    """
    predecessors = defaultdict(set)
    successors = defaultdict(set)
    
    # current mappings of packet tags
    registry = ObjectRegistry()
    packet_tags = dict()
    
    # global set of candidates for happens-before edges
    latest_events = []
    
    # lookup tables for indexing into the latest_events set
    latest_events_by_type = defaultdict(set)
    latest_events_by_type_dpid = defaultdict(set)
    latest_events_by_tag = defaultdict(set)
    latest_events_by_type_tag = defaultdict(set)
    latest_events_by_type_dpid_cid_msg = defaultdict(set)
    latest_events_by_dpid_tag = defaultdict(set)
    latest_events_by_dpid_msg = defaultdict(set)
    latest_events_by_dpid_bufferid = defaultdict(set)
    latest_events_by_type_msgtype_dpid = defaultdict(set)
    # TODO JM: remove unused
    
    latest_events_lookup_tables = [
                                   #( field name,
                                   #  condition to be included,
                                   #  search key
                                   #),
                                   (latest_events_by_type, 
                                    lambda x: hasattr(x, 'type'), 
                                    lambda x: x.type ),
                                   (latest_events_by_type_dpid, 
                                    lambda x: hasattr(x, 'type') and hasattr(x, 'dpid'), 
                                    lambda x: (x.type, x.dpid) ),
                                   (latest_events_by_tag, 
                                    lambda x: x in packet_tags, 
                                    lambda x: packet_tags[x] ),
                                   (latest_events_by_type_tag, 
                                    lambda x: hasattr(x, 'type') and x in packet_tags, 
                                    lambda x: (x.type, packet_tags[x]) ),
                                   (latest_events_by_type_dpid_cid_msg, 
                                    lambda x: hasattr(x, 'type') and hasattr(x, 'dpid') and hasattr(x, 'cid') and hasattr(x, 'msg'), 
                                    lambda x: (x.type, x.dpid, x.cid, x.msg) ),
                                   (latest_events_by_dpid_tag, 
                                    lambda x: hasattr(x, 'dpid') and x in packet_tags, 
                                    lambda x: (x.dpid, packet_tags[x]) ),
                                   (latest_events_by_dpid_msg,
                                    lambda x: hasattr(x, 'dpid') and hasattr(x, 'msg'), 
                                    lambda x: (x.dpid, x.msg) ),
                                   (latest_events_by_dpid_bufferid,
                                    lambda x: hasattr(x, 'dpid') and hasattr(x, 'buffer_id'), 
                                    lambda x: (x.dpid, x.buffer_id) ),
                                   (latest_events_by_type_msgtype_dpid,
                                    lambda x: hasattr(x, 'type') and hasattr(x, 'msg_type') and hasattr(x, 'dpid'), 
                                    lambda x: (x.type, x.msg_type, x.dpid) )
                                   ]
    
    # mapping of barrier_req_ev -> events that occurred before a specific BARRIER_REQUEST in the trace
    barrier_unordered_events = defaultdict(set)
    
    # mapping of dpid -> events that have occurred before having read the next barrier request.
    new_unordered_events = defaultdict(set)
    
    # dpid -> barrier response
    current_barrier_response = dict()
    
    # injected vendor events
    injected_vendor_out_events = dict()
    injected_vendor_in_events = dict()
    
    # mapping injected in events -> PACKET_IN events
    packet_in_events = dict()
    
    def _injected_vendor_out_events_add(ev):
      """ Call this for all OF msgs sent from controller
      """
      dpid = ev.dpid
      cid = ev.cid
      msg_out = ev.msg_out
      
      injected_vendor_out_events[(dpid,cid,msg_out)] = ev
      
    def _injected_vendor_in_events_add(ev):
      """ Call this for all OF msgs sent from controller
      """
      dpid = ev.dpid
      cid = ev.cid
      msg_in = ev.msg_in
      msg_in_floodlight_sw_id = ev.msg_in_floodlight_sw_id
      
      injected_vendor_in_events[(dpid,cid,msg_in,msg_in_floodlight_sw_id)] = ev
    
    def _new_unordered_events_add(ev):
      """ Call this for all OF msgs sent from controller
      """
      dpid = ev.dpid
      assert ev.type == EventType.TraceOfMessageFromController
      if ev.msg_type == MsgType.BARRIER_REQUEST:
        # add events
        barrier_unordered_events[ev].update(new_unordered_events[dpid])
        # clear
        del new_unordered_events[dpid]
      else:
        new_unordered_events[dpid].add(ev)
        
    def _current_barrier_response_add(ev):
      assert ev.type == EventType.TraceOfMessageToController
      assert ev.msg_type == MsgType.BARRIER_REPLY
      current_barrier_response[ev.dpid] = ev

    
    def _latest_events_add(ev):
      """ Call this for all events
      """
      latest_events.append(ev)
      for entry in latest_events_lookup_tables:
        table = entry[0]
        condition = entry[1]
        key = entry[2]
        if condition(ev):
          table[key(ev)].add(ev)
          
    def _latest_events_remove(ev):
      latest_events.remove(ev)
      for entry in latest_events_lookup_tables:
        table = entry[0]
        condition = entry[1]
        key = entry[2]
        if condition(ev):
          table[key(ev)].remove(ev)
          
    def _latest_events_add_or_replace(ev, equals_fun, assert_once=True):
      to_replace = []
      for i in latest_events:
        try: #comparison might fail
          if equals_fun(ev,i):
            to_replace.add(i)
        except:
          pass
      if assert_once:
        assert len(to_replace) < 2
      for i in to_replace:
        _latest_events_remove(i)
      _latest_events_add(ev)
      
    
    # 
    # Add HB edge
    #
    def _add_happensbefore(ev_before, ev_after):
      """
      Add HB edge, where ev_before happensbefore ev_after.
      
      Assert that ev_before must be of one of the types that were manually 
      determined to be possible types for events that happen before ev_after.
      
      Note: The list of allowed types was determined manually by looking through
            the source code of the STS switch. It is therefore very specific to
            the STS implementation and our particular instrumentation.
      """
      assert ev_before.type in predecessor_types[ev_after.type] 
      predecessors[ev_after].add(ev_before)
      successors[ev_before].add(ev_after)

    def _select_single_event(ev, candidates):
      if candidates is not None and len(candidates) > 0:
        ret = []
        for i in candidates:
          if i.type in predecessor_types[ev.type]:
            ret.append(i)
        if len(ret) > 0:
          assert len(ret) == 1
          return ret[0]
      return None
    
    def _select_multiple_events(ev, candidates):
      if candidates is not None and len(candidates) > 0:
        ret = []
        for i in candidates:
          if i.type in predecessor_types[ev.type]:
            ret.append(i)
        if len(ret) > 0:
          return ret
      return None
    
    def _select_matching_ports(ev, candidates):
      """
      Check that the dataplane traffic is actually possible by looking at the
      topology.
      
      The instrumentation adds topology information to each send or receive
      event, such as port numbers, connection status, and the node that is
      connected at the other end. This is 
      """
      ret = []
      for before in candidates:
        result = True
        result = result and (ev.packet == before.packet)
  
        result = result and (before.is_connected)
        result = result and (ev.is_connected)
        
        before_self_loc = (before.is_switch, before.node, before.port)
        before_other_loc = (before.connected_is_switch, before.connected_node, before.connected_port)
        ev_self_loc = (ev.is_switch, ev.node, ev.port)
        ev_other_loc = (ev.connected_is_switch, ev.connected_node, ev.connected_port)
        
        result = result and (before_self_loc == ev_other_loc)
        result = result and (before_other_loc == ev_self_loc)
        if result:
          ret.append(before)
      if len(ret) > 0:
        return ret
      return None

    #
    # Rules:
    #
    # Let E1 < E2 be the ordering of events as they appear in the trace.
    # Define happens-before ordering <: in a trace R as follows:
    #   - E1 <: E2 iff E1 < E2 and one of the following rules holds.
    #
    
    def _rule_00_trivial(ev):
      """
      Some events are split into two parts, where the second part just
      points to the first.
      """
      before = self.events_by_id[ev.precursor_id]
      before = _select_single_event(ev,before)
      return before

    
    def _rule_01_switch_processing(ev):
      """
      Packet tags establish HB relationships within a single switch.
      
      Each incoming packet is tagged when:
       - it arrives from the dataplane
       - it arrives from the controller (as a raw packet)
       - it is read from the switch's buffer
       
      The switch's instrumentation generates sufficient events to track all
      changes that the switch makes to a tagged packet. This guarantees that
      the packet will have the same tag until the switch is done processing
      the packet, even if it's contents change.
      
      An STS switch is single-threaded and does not fork. Thus, each returned 
      event should be used exactly once, i.e. it will have one successor and 
      happen before one other event with the same tag.
      
      Note that a packet's tag is not preserved through buffer write/reads, so
      we do not add any HB relationships such as buffer write :< buffer read, as
      this would not account for the involvement of the controller.
      
      When the switch has processed a packet, there are multiple possibilities:
       - it can be dropped (in this case no further events exist)
       - it can be stored in the buffer and sent to the controller
       - it can be sent as a raw packet to the controller
       - it can be forwarded/actions
       
       The last such event can then used by other rules to add a HB relationship.
       
       This rule:
        - looks up the latest event X with:
          1. the same switch as ev
          2. the same tag as ev
          
      return X
      X should be removed from latest_events.
      """
      
      candidates = None
      types_use_tag = [EventType.TraceDpPacketOutSwitch,
                        EventType.TraceDpPacketInSwitch,
                        EventType.TraceOfGeneratePacketIn,
                        EventType.TraceFlowTableRuleMatch,
                        EventType.TraceFlowTableRuleTouch,
                        EventType.TracePacketActionModificationBegin,
                        EventType.TracePacketActionModificationEnd,
                        EventType.TracePacketActionOutput,
                        EventType.TracePacketActionResubmit,
                        EventType.TracePacketBufferWritePacket,
                        EventType.TracePacketBufferFlushPacket]
      
      types_use_msg = [EventType.TraceOfHandleFlowModFromBuffer,
                       EventType.TraceOfHandlePacketOutFromRaw,
                       EventType.TraceOfHandlePacketOutFromBuffer,
                       EventType.TraceOfMessageToController,
                       EventType.TraceFlowTableModification]
      
      types_use_bufferid = [EventType.TracePacketBufferReadPacket,
                            EventType.TracePacketBufferReadError]
      
      if ev.type in types_use_tag:
        if ev in packet_tags:
          candidates = latest_events_by_dpid_tag[(ev.dpid, packet_tags[ev])]
      
      elif ev.type in types_use_msg:
        candidates = latest_events_by_dpid_msg[(ev.dpid, ev.msg)]
      
      elif ev.type in types_use_bufferid:
        candidates = latest_events_by_dpid_bufferid[(ev.dpid, ev.buffer_id)]
        
      before = _select_single_event(ev,candidates)
      if before is not None:
        _latest_events_remove(before)
      return before
      
    def _rule_02_dataplane_links(ev):
      """
      Packets are sent before they are received.
      
      The instrumentation adds a packet tag to each packet sent on the
      dataplane, and to each packet received from the dataplane. Thus
      it is easily possible to match sent and received packets.
      
      Note that the tags will only be identical if the Python object (packet) 
      sent has the same id() as the Python object that is received. Thus this
      only works if both send/receive events run in the same Python interpreter
      (such as STS), but will not work if an actual network were to be used.
      
      This rule:
        - looks up the latest event X with:
          1. type DpOut
          2. the same tag as ev
          
      return X
      X should be removed from latest_events.
      """
      types = [EventType.TraceDpPacketInHost,
               EventType.TraceDpPacketInSwitch]
      
      before = None
      if ev.type in types:
        if ev in packet_tags:
          candidates = latest_events_by_type_tag[(EventType.TraceDpPacketOutHost, packet_tags[ev])]
          
          candidates = _select_matching_ports(ev,candidates)
          before = _select_single_event(ev,candidates)
          if before is None:          
            candidates = latest_events_by_type_tag[(EventType.TraceDpPacketOutSwitch, packet_tags[ev])]
            candidates = _select_matching_ports(ev,candidates)
            before = _select_single_event(ev,candidates)
          
      if before is not None:
        _latest_events_remove(before)
      return before
    
    def _rule_03_floodlight_proxy(ev):
      """
      Floodlight can only process one request at a time per connection.
      
      The HappensBeforeProxy Floodlight module generates additional Openflow
      messages of type VENDOR. For each Openflow message Floodlight generates,
      an additional message is injected that contains information about which
      PACKET_IN was responsible.
      
      Note: The injected packets will occur in the trace *before* the
            outgoing Openflow message was sent from the controller, but
            *after* the incoming Openflow message was received by the 
            controller.
      
      Therefore this rule should be called for the actual events for 
      PACKET_OUT, FLOW_MOD and BARRIER_REQUEST messages, not the
      VENDOR messages.
      
      This rule:
        - looks up the latest event A with:
          1. type VENDOR
          2. A.msg_out == ev.msg
          3. A.dpid == ev.dpid
          4. A.cid == ev.cid
          -> This is the injected event for our event
          
        - looks up the latest event X with:
          1. type PACKET_IN
          2. the same packet bitstring as A.msg_in
          3. for which a VENDOR event B has been registered with:
             a) B.msg_in == X.msg
             b) B.dpid == X.dpid
             c) B.floodlight_switch_id == A.floodlight_switch_id
             -> This is the injected event for the PACKET_IN
          -> This is the predecessor
      
      return X
      A should be removed from latest_events.
      B should not be removed from latest_events.
      X should not be removed from latest_events.
       -> However, if a new event is in the trace that is indistinguishable
          from X, it should replace the current X.
          Indistinguishable in this context means these fields are the same:
            - dpid
            - cid
            - msg
      """
      if ev.type == EventType.TraceOfMessageFromController:
        msg_types = [MsgType.PACKET_OUT,
                     MsgType.BARRIER_REQUEST,
                     MsgType.FLOW_MOD]
        if ev.msg_type in msg_types:
          dpid = ev.dpid
          cid = ev.cid
          msg = ev.msg
          if (dpid,cid,msg) in injected_vendor_out_events:
            out_vendor_event = injected_vendor_out_events[(dpid,cid,msg)]
            del injected_vendor_out_events[(dpid,cid,msg)] # remove, it's only used once
            
            msg_in = out_vendor_event.msg_in
            msg_in_floodlight_sw_id = out_vendor_event.msg_in_floodlight_sw_id
            
            in_vendor_event = injected_vendor_in_events[(dpid,cid,msg_in,msg_in_floodlight_sw_id)]
            
            packet_in_ev = packet_in_events[in_vendor_event]
            
            before = _select_single_event(ev,packet_in_ev)
            return before

    def _rule_04_barrier_response_after(ev):
      """
      All messages that were received before a BARRIER_REQUEST message
      happen-before the corresponding BARRIER_REPLY message.
      
      Should be called for barrier responses only.
      
      Diagram:
          in->out     ->response1
          in->flow_mod->response1
          in->out     ->response1
          in->barrier ->response1
          in-> . . .            -> response2 ...
          ----------
          In -> packet out -> response
          In -> flow_mod   -> response
                barrier    -> response
                flow_mod   -> response2
          In2-> barrier    -> response2
      
      Note: For this to work the following dicts need to be up to date:
              - barrier_unordered_events[]
              - new_unordered_events[]
              
      This rule:
        - looks up the event A in latest_events with:
          1. type = BARRIER_REQUEST
          2. dpid = ev.dpid
        - looks up all events X that occurred before the barrier request A:
          1. listed in barrier_unordered_events[A.dpid]

      return all X events
      A should be removed from barrier_requests, it is no longer needed.
      All X events should be removed from barrier_unordered_events.
      
      """
      if ev.type == EventType.TraceOfMessageFromController:
        if ev.msg_type == MsgType.BARRIER_REPLY:
          # get matching request
          barrier_request = latest_events_by_type_msgtype_dpid[(EventType.TraceOfMessageFromController, MsgType.BARRIER_REQUEST, ev.dpid)]
          before_events = barrier_unordered_events[barrier_request]
          del barrier_unordered_events[barrier_request]
          
          before_events = _select_multiple_events(ev, before_events)
          return before_events
      return None
        
    def _rule_05_barrier_response_before(ev):
      """
      The latest BARRIER_REPLY event for a given switch happens-before
      all messages received after the corresponding BARRIER_REQUEST.
      
      This rule:
        - looks up the latest event X with:
          1. type BARRIER_REPLY
          2. the same switch as ev
      
      return X
      X should not be removed from latest_events.
      """
      if ev.type == EventType.TraceOfMessageFromController:
        if ev.dpid in latest_barrier_response:
          before = latest_barrier_response[ev.dpid]
          before = _select_single_event(ev, before)
          return before
        
      return None
      
    def _rule_06_host_processing(ev):
      pass # not implemented
      
    #
    # Event types
    #
    
    def _case_TraceTagPacket(ev):
      """
      Special case: Not used for happens-before, but merely to generate
      auxiliary packet information (packet_tags).
      """
      obj = ev.packet_obj_id
      reg_event_id = ev.packet_register_event_id
      
      tag = None
      if reg_event_id is not None:
        # we are replacing an already existing object, lookup the original object
        # reg_event_id is an event id
        reg_event = self.events_by_id[reg_event_id]
        reg_obj = reg_event.packet_obj_id
        tag = registry.lookup(reg_obj)
      
      tag = registry.register(obj, tag)
      packet_tags[ev] = tag
      
    def _case_TraceUntagPacket(ev):
      """
      See _case_TraceTagPacket
      """
      obj = ev.packet_obj_id # may be None
      reg_event_id = ev.packet_register_event_id # may be None
      assert (obj is not None) or (reg_event_id is not None)
      
      if reg_event_id is not None:
        reg_event = self.events_by_id[reg_event_id]
        reg_obj = reg_event.packet_obj_id
        assert (obj is None or obj == reg_obj)
        obj = reg_obj

      registry.deregister(obj)

    def _check_rule_00(ev):
      before = _rule_00_trivial(ev)
      if before is not None:
        _add_happensbefore(before, ev)
        
    def _check_rule_01(ev):
      before = _rule_01_switch_processing(ev)
      if before is not None:
        _add_happensbefore(before, ev)
      
    def _check_rule_02(ev):
      before = _rule_02_dataplane_links(ev)
      if before is not None:
        _add_happensbefore(before, ev)
    
    def _check_rule_01_then_02(ev):
      before = _rule_01_switch_processing(ev)
      if before is not None:
        _add_happensbefore(before, ev)
      else:
        before = _rule_02_dataplane_links(ev)
        if before is not None:
          _add_happensbefore(before, ev)
        
    def _check_rule_03(ev):
      before = _rule_03_floodlight_proxy(ev)
      if before is not None:
        _add_happensbefore(before, ev)
        
    def _check_rule_04(ev):
      before_events = _rule_04_barrier_response_after(ev)
      if before_events is not None:
        for i in before_events:
          _add_happensbefore(i, ev)
        
    def _check_rule_05(ev):
      before = _rule_05_barrier_response_before(ev)
      if before is not None:
        _add_happensbefore(before, ev)
        

    def _case_TraceDpPacketOutHost(ev):
      # not implemented: check TracePacketHostResponseEnd
      _latest_events_add(ev)
    def _case_TraceDpPacketOutSwitch(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)
    def _case_TraceDpPacketInHost(ev):
      _check_rule_02(ev)
      _latest_events_add(ev)
    def _case_TraceDpPacketInSwitch(ev):
      _check_rule_01_then_02(ev)
      _latest_events_add(ev)
    def _case_TracePacketHostResponseBegin(ev):
      pass # not implemented
    def _case_TracePacketHostResponseEnd(ev):
      pass # not implemented
    def _case_OfHandleVendorHb(ev):
      if hasattr(ev, 'msg_out'):
        _injected_vendor_out_events_add(ev)
      else:
        packet_in_ev = latest_events_by_type_dpid_cid_msg[(ev.dpid, ev.cid, ev.msg)]
        packet_in_events[ev] = packet_in_ev
        _injected_vendor_in_events_add(ev)
      # do not add to latest_events    
    def _case_TraceOfHandleFlowModFromBuffer(ev):
      _check_rule_01_then_02(ev)
      _latest_events_add(ev)
    def _case_TraceOfHandlePacketOutFromRaw(ev):
      _check_rule_01_then_02(ev)
      _latest_events_add(ev)
    def _case_TraceOfHandlePacketOutFromBuffer(ev):
      _check_rule_01_then_02(ev)
      _latest_events_add(ev)
    def _case_TraceOfGeneratePacketIn(ev):
      _check_rule_01_then_02(ev)
      _latest_events_add(ev)
    def _case_TraceOfMessageToController(ev):
      _check_rule_01(ev)
      if ev.msg_type == MsgType.BARRIER_REPLY:
        _check_rule_04(ev)
        _current_barrier_response_add(ev)
      elif ev.msg_type == MsgType.PACKET_IN:
        _latest_events_add_or_replace(ev, lambda a,b: (a.dpid, a.cid, a.msg) == (b.dpid, b.cid, b.msg), True)
    def _case_TraceOfMessageFromController(ev):
      _new_unordered_events_add(ev)
      _check_rule_03(ev)
      _latest_events_add(ev)
    def _case_TraceFlowTableModification(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)
    def _case_TraceFlowTableRuleExpiration(ev):
      pass # not used
    def _case_TraceFlowTableRuleMatch(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)               
    def _case_TraceFlowTableRuleTouch(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)
    def _case_TracePacketActionModificationBegin(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)
    def _case_TracePacketActionModificationEnd(ev):
      _check_rule_00(ev)
      _latest_events_add(ev)
    def _case_TracePacketActionOutput(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)
    def _case_TracePacketActionResubmit(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)         
    def _case_TracePacketBufferReadPacket(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)       
    def _case_TracePacketBufferReadError(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)        
    def _case_TracePacketBufferWritePacket(ev):
      _check_rule_01(ev)
      _latest_events_add(ev)      
    def _case_TracePacketBufferFlushPacket(ev):  
      _check_rule_01(ev)
      _latest_events_add(ev)
    def _case_default(ev):
      pass
    
    cases = {
        EventType.TraceTagPacket:                _case_TraceTagPacket,
        EventType.TraceUntagPacket:              _case_TraceUntagPacket,
        EventType.TraceDpPacketOutHost:               _case_TraceDpPacketOutHost,
        EventType.TraceDpPacketOutSwitch:             _case_TraceDpPacketOutSwitch,
        EventType.TraceDpPacketInHost:                _case_TraceDpPacketInHost,
        EventType.TraceDpPacketInSwitch:              _case_TraceDpPacketInSwitch,
        EventType.TracePacketHostResponseBegin:       _case_TracePacketHostResponseBegin,
        EventType.TracePacketHostResponseEnd:         _case_TracePacketHostResponseEnd,
        EventType.OfHandleVendorHb:                   _case_OfHandleVendorHb,
        EventType.TraceOfGeneratePacketIn:            _case_TraceOfGeneratePacketIn,
        EventType.TraceOfHandleFlowModFromBuffer:     _case_TraceOfHandleFlowModFromBuffer,
        EventType.TraceOfHandlePacketOutFromRaw:      _case_TraceOfHandlePacketOutFromRaw,
        EventType.TraceOfHandlePacketOutFromBuffer:   _case_TraceOfHandlePacketOutFromBuffer,
        EventType.TraceOfMessageToController:         _case_TraceOfMessageToController,
        EventType.TraceOfMessageFromController:       _case_TraceOfMessageFromController,
        EventType.TraceFlowTableModification:         _case_TraceFlowTableModification,
        EventType.TraceFlowTableRuleExpiration:  _case_TraceFlowTableRuleExpiration,
        EventType.TraceFlowTableRuleMatch:                _case_TraceFlowTableRuleMatch,
        EventType.TraceFlowTableRuleTouch:                _case_TraceFlowTableRuleTouch,
        EventType.TracePacketActionModificationBegin: _case_TracePacketActionModificationBegin,
        EventType.TracePacketActionModificationEnd:   _case_TracePacketActionModificationEnd,
        EventType.TracePacketActionOutput:            _case_TracePacketActionOutput,
        EventType.TracePacketActionResubmit:          _case_TracePacketActionResubmit,
        EventType.TracePacketBufferReadPacket:        _case_TracePacketBufferReadPacket,
        EventType.TracePacketBufferReadError:             _case_TracePacketBufferReadError,
        EventType.TracePacketBufferWritePacket:       _case_TracePacketBufferWritePacket,
        EventType.TracePacketBufferFlushPacket:        _case_TracePacketBufferFlushPacket
    }
    
    for ev in self.events:
      # run case
      if ev.type not in [EventType.TraceTagPacket, EventType.TraceUntagPacket]:
        #update tags
        if hasattr(ev, 'packet_register_event_id'):
          reg_event = self.events_by_id[ev.packet_register_event_id]
          tag = packet_tags[reg_event]
          packet_tags[ev] = tag
      cases.get(ev.type, _case_default)(ev)
      
    self.predecessors = predecessors
    self.successors = successors
    
  def store_graph(self, filename):
    dot_lines = []
    edges = 0
    dot_lines.append("digraph G {\n");
    for i in self.events:
      if i.type not in [EventType.TraceTagPacket, 
                        EventType.TraceUntagPacket,
                        EventType.OfHandleVendorHb]:
        try:
          dot_lines.append('{0} [label="{0}\\n{1}\\n{2}"];\n'.format(i.id,EventType.keys()[i.type],MsgType.keys()[i.msg_type]))
        except:
          dot_lines.append('{0} [label="{0}\\n{1}"];\n'.format(i.id,EventType.keys()[i.type]))
    for (k,v) in self.predecessors.iteritems():
      for i in v:
        dot_lines.append('    {} -> {};\n'.format(i.id,k.id))
        edges += 1
    dot_lines.append("}\n");
    pprint.pprint(dot_lines)
    with open(filename, 'w') as f:
      f.writelines(dot_lines)
    print "Wrote out " + str(edges) + " edges."
    

class Main(object):
  
  def __init__(self,filename):
    self.filename = filename
    self.results_dir = os.path.dirname(os.path.realpath(self.filename))
    self.output_filename = self.results_dir + "/" + "hb.dot"
  
  def run(self):
    self.graph = HappensBeforeGraph()
    self.graph.load_trace(self.filename)
    self.graph.evaluate_rules()
    self.graph.store_graph(self.output_filename)
    
if __name__ == '__main__':
  if len(sys.argv) < 2:
    print "Usage: read_trace.py <file>"
  else:
    print "Using file {0}".format(sys.argv[1])
    main = Main(sys.argv[1])
    main.run()
    
