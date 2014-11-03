#!/usr/bin/env python
import sys
import os
import subprocess
import shlex
import pyparsing as pp
from collections import OrderedDict
import itertools
import datetime, time
import functools
import pprint

# sys.path.append(os.path.join(os.path.dirname(__file__), "pox"))
# import pox.openflow.libopenflow_01 as of
# import pox.openflow.flow_table


# see: http://stackoverflow.com/a/1695250/202504
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    key_names = reverse
    @classmethod
    def keys(cls):
       return key_names
    enums['keys'] = keys
    return type('Enum', (), enums)

Cmd = enum('CREATE',
            'RESET',
            'CLEAR',
            'TRACE',
            'DUMP',
            'OF_ADD',
            'OF_DEL',
            'OF_MOD',
            'OF_BAR'
)

class MainApp(object):
    def __init__(self):
        pass

    def run(self):
        env = os.environ
        # print env
        if 'OVS_SYSCONFDIR' not in env:
            print "OVS sandbox not found. See the readme for instructions."
            exit()
        sw = OvsSwitch(SwitchDesc('br0',5))
        sw.executeCommand(Command(Cmd.RESET))
        sw2 = OvsSwitch(SwitchDesc('br1',5))
        sw2.executeCommand(Command(Cmd.RESET))

        comparator = FlowComparator(sw2)

        testcases = []
        # Do they overlap?
        testcases.append(IntersectionNonEmptyTestCase(comparator,
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.1.0 actions=1'),
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.1.1/24 actions=2'),
                                                      True))
        testcases.append(IntersectionNonEmptyTestCase(comparator,
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24 actions=1'),
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16 actions=2'),
                                                      True))
        testcases.append(IntersectionNonEmptyTestCase(comparator,
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24 actions=1'),
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16, dl_vlan=20 actions=2'),
                                                      True))
        testcases.append(IntersectionNonEmptyTestCase(comparator,
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24, dl_vlan=5 actions=1'),
                                                      FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16, dl_vlan=20 actions=2'),
                                                      False))
        # Is a a subset of b?
        testcases.append(SubsetTestCase(comparator,
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24 actions=1'),
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16, dl_vlan=20 actions=2'),
                                        False))
        testcases.append(SubsetTestCase(comparator,
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16, dl_vlan=20 actions=2'),
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24 actions=1'),
                                        False))
        testcases.append(SubsetTestCase(comparator,
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24 actions=1'),
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16 actions=2'),
                                        True))
        testcases.append(SubsetTestCase(comparator,
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/16 actions=1'),
                                        FlowDescription('table=0, priority=1, tcp,nw_src=192.168.0.0/24 actions=2'),
                                        False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.RESET), # command A
                                  Command(Cmd.RESET), # command B
                                  [], # commands executed before each test
                                  True)) # expected result for commutativity
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1 actions=1')),
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=2 actions=2')),
                                  [],
                                  True))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.TRACE,FlowDescription('tcp,nw_src=192.168.1.0,nw_dst=192.168.1.1')),
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_src=192.168.1.0 actions=2')),
                                  [],
                                  False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.TRACE,FlowDescription('tcp,nw_src=192.168.1.0,nw_dst=192.168.1.1')),
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_src=192.168.1.0,nw_dst=192.168.0.1 actions=2')),
                                  [],
                                  True))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.TRACE,FlowDescription('tcp,nw_src=192.168.1.0,nw_dst=192.168.1.1')),
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_src=192.168.1.0,nw_dst=192.168.0.0/16 actions=2')),
                                  [],
                                  False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.0.1')),
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=8, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  [Command(Cmd.OF_ADD,FlowDescription('table=0, priority=24, tcp,nw_dst=10.0.0.0/24 actions=1'))],
                                  True))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.0.1')),
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=8, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  [],
                                  False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  Command(Cmd.OF_DEL,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  [],
                                  False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0 actions=2')),
                                  Command(Cmd.OF_DEL,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  [],
                                  False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  Command(Cmd.OF_DEL,FlowDescription('table=0, priority=2, tcp,nw_dst=10.0.0.0/8 actions=2')),
                                  [],
                                  False))
        #priorities are not used without _STRICT
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0 actions=2')),
                                  Command(Cmd.OF_DEL,FlowDescription('table=0, priority=2, tcp,nw_dst=10.0.0.0 actions=2')),
                                  [],
                                  False))
        testcases.append(CommutativityTestCase(sw,
                                  Command(Cmd.OF_ADD,FlowDescription('table=0, priority=1, tcp,nw_dst=10.0.0.0 actions=2')),
                                  Command(Cmd.OF_DEL,FlowDescription('table=0, priority=2, tcp,nw_dst=10.0.0.0'),strict=True),
                                  [],
                                  True))

        for tc in testcases:
            result,info_str = tc.evaluate()
            if result is True:
                print 'Pass. ' + info_str
            elif result is False:
                print 'Fail. ' + info_str
            else:
                print '????. ' + info_str


        command_list = [
            Command(Cmd.RESET),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_src=192.168.1.0,nw_dst=192.168.1.1'))
        ]
        initials_list = [
            []
        ]
        suite = CommutativityTestSuite(sw,comparator,command_list,initials_list)
        suite.evaluate_all()

class CommutativityTestSuite(object):
    """
    Given a list of commands and a list of initial commands, generate testcases for all possible combinations
    """
    def __init__(self,switch,comparator,commands,initials=None):
        self.switch = switch
        self.comparator = comparator
        self.commands = commands
        if commands == None:
            commands = []
        self.initials = initials
        if initials == None:
            initials = [[]]
        self.predictor = CommutativityPredictor(self.switch,self.comparator)

    def evaluate_all(self):
        testcases = []
        for i in self.initials:
            for a,b in itertools.combinations_with_replacement(self.commands,2):
                current = CommutativityTestCase(self.switch,a,b,i)
                current.expected = self.predictor.predict(current)
                testcases.append(current)
        total = len(testcases)
        passed = 0
        failed = 0
        na = 0
        print 'Generated ' + str(total) + ' testcases.'
        for tc in testcases:
            result,info_str = tc.evaluate()
            if result is True:
                passed += 1
                print 'Pass. ' + info_str
            elif result is False:
                failed += 1
                print 'Fail. ' + info_str
                print str(tc)
            else:
                na += 1
                print '????. ' + info_str
                print str(tc)
        print 'Passed: ' + str(passed) + ', Failed: ' + str(failed) + ', n/a: ' + str(na) + ', Total ' + str(total)


class CommutativityPredictor(object):
    def __init__(self,switch,comparator):
        self.switch = switch
        self.comparator = comparator

    def predict(self,testcase):
        a = testcase.a
        b = testcase.b
        initial = testcase.initial

        x = a
        y = b
        if a > b:
            x = b
            y = a


        #
        # TODO: transfer rules from the document to here
        #

        if x.type == Cmd.RESET:
            if y.type == Cmd.RESET:
                return True  #always commutes

            if y.type == Cmd.TRACE:
                return None # depends on whether or not the TRACE matches any rule at all

            if y.type == Cmd.OF_ADD:
                return False

            if y.type == Cmd.OF_DEL:
                return None # depends: if everything or nothing was deleted, then it commutes

            if y.type == Cmd.OF_MOD:
                return None # depends: if nothing was modified, then it commutes

        if x.type == Cmd.TRACE:
            if y.type == Cmd.TRACE:
                return True #always commutes

            if y.type == Cmd.OF_ADD:
                return None

            if y.type == Cmd.OF_DEL:
                return None

            if y.type == Cmd.OF_MOD:
                return None

        if x.type == Cmd.OF_ADD:
            if y.type == Cmd.OF_ADD:
                return None

            if y.type == Cmd.OF_DEL:
                return None

            if y.type == Cmd.OF_MOD:
                return None

        if x.type == Cmd.OF_DEL:
            if y.type == Cmd.OF_DEL:
                return None

            if y.type == Cmd.OF_MOD:
                return None

        if x.type == Cmd.OF_MOD:
            if y.type == Cmd.OF_MOD:
                return None
        return None

class IntersectionNonEmptyTestCase(object):
    def __init__(self,comparator,a,b,expected=None):
        self.comparator = comparator
        self.a = a
        self.b = b
        self.expected = expected

    def evaluate(self):
        nonempty = self.comparator.is_intersection_nonempty(self.a,self.b)
        info_str = ('intersects.' if nonempty else 'does not intersect.')
        if self.expected is not None:
            if nonempty == self.expected:
                return (True,info_str)
            else:
                return (False,info_str)
        else:
            return (None,info_str)

class SubsetTestCase(object):
    def __init__(self,comparator,a,b,expected=None):
        self.comparator = comparator
        self.a = a
        self.b = b
        self.expected = expected

    def evaluate(self):
        nonempty = self.comparator.is_subset(self.a,self.b)
        info_str = ('is subset.' if nonempty else 'is not a subset.')
        if self.expected is not None:
            if nonempty == self.expected:
                return (True,info_str)
            else:
                return (False,info_str)
        else:
            return (None,info_str)

class CommutativityTestCase(object):
    def __init__(self,switch,a,b,initial=None,expected=None):
        self.switch = switch
        self.a = a
        self.b = b
        self.initial = initial
        if initial is None:
            self.initial = []
        self.expected = expected

    def execute_check_affected(self,cmd):
        if cmd != Cmd.TRACE:
            # we will not get information about the affected rules in the result
            before = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
            result = self.switch.executeCommand(cmd)
            after = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))

            #compute set of affected rules in the before set
            before_set = set(before.dumped_flows)
            after_set = set(after.dumped_flows)

            result.removed = before_set.difference(after_set)
            result.added = after_set.difference(before_set)
            result.affected_flows = before_set.symmetric_difference(after_set)

            return result
        else:
            return self.switch.executeCommand(cmd)

    def evaluate(self):
        # print "Starting testcase"
        self.switch.executeCommand(Command(Cmd.RESET))
        for cmd in self.initial:
            self.switch.executeCommand(cmd)

        # print "Running a->b"
        first_a = self.execute_check_affected(self.a)
        first_b = self.execute_check_affected(self.b)

        first_dump = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))

        self.switch.executeCommand(Command(Cmd.RESET))
        for cmd in self.initial:
            self.switch.executeCommand(cmd)

        # print "Running b->a"
        second_b = self.execute_check_affected(self.b)
        second_a = self.execute_check_affected(self.a)

        second_dump = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))

        # Commutativity:
        # - All traces execute the same actions. Here we can do direct string comparison, as the list of actions is ordered.
        # - The flow tables are the same afterwards

        # Preliminary
        commutes = True

        if self.a.type == Cmd.TRACE:
            # compare first_a with second_a
            if first_a.traced_actions != second_a.traced_actions:
                commutes = False
                if self.expected != False:
                    print 'Actions for a not the same: '+str(first_a.traced_actions)+' vs. '+str(second_a.traced_actions)

        if self.b.type == Cmd.TRACE:
            # compare first_b with second_b
            if first_b.traced_actions != second_b.traced_actions:
                commutes = False
                if self.expected != False:
                    print 'Actions for b not the same: '+str(first_b.traced_actions)+' vs. '+str(second_b.traced_actions)

        #compare first_dump to second_dump
        first_set = set(first_dump.dumped_flows)
        second_set = set(second_dump.dumped_flows)
        if not first_set == second_set:
            commutes = False
            # print "Flow tables not the same"
            # print "In first but not second:"
            # print list(first_set.difference(second_set))
            # print "In second but not first:"
            # print list(second_set.difference(first_set))

        # print "Done with testcase"
        info_str = ('commutes.' if commutes else 'does not commute.') + ' Rules added/removed: ' \
        '(' + '+'+str(len(first_a.added))+'/-'+str(len(first_a.removed))+', '+'+'+str(len(first_b.added))+'/-'+str(len(first_b.removed))+')' + ' vs.' \
        '(' + '+'+str(len(second_a.added))+'/-'+str(len(second_a.removed))+', '+'+'+str(len(second_b.added))+'/-'+str(len(second_b.removed))+')'

        if self.expected is not None:
            if commutes == self.expected:
                return (True,info_str)
            else:
                return (False,info_str)
        else:
            return (None,info_str)

    def __str__(self):
        return '(\n\t' + str(self.a) + ',\n\t' + str(self.b) + ',\n\tinitial=' + str(self.initial) + ',\n\texpected=' + str(self.expected) + '\n)'

class FlowComparator(object):
    def __init__(self,switch):
        self.switch = switch

    def _reset(self):
        self.switch.executeCommand(Command(Cmd.RESET))

    def is_intersection_nonempty(self,s,t):
        # is the intersection(s,t) non-empty?
        self._reset()
        s.actions = OrderedDict([('1',None)])
        t.actions = OrderedDict([('2',None)])
        result_s = self.switch.executeCommand(Command(Cmd.OF_ADD,s))
        t.fields['check_overlap'] = None #enables overlap checking
        result_t = self.switch.executeCommand(Command(Cmd.OF_ADD,t))
        if result_t.overlaps is True:
            return True
        else:
            return False

    def is_subset(self,s,t):
        # is s a subset of t?
        # TODO: this can be done much easier
        self._reset()
        s.actions = OrderedDict([('1',None)])
        t.actions = OrderedDict([('2',None)])
        result_t = self.switch.executeCommand(Command(Cmd.OF_ADD,t))
        result_s = self.switch.executeCommand(Command(Cmd.OF_ADD,s))
        before = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
        result = self.switch.executeCommand(Command(Cmd.OF_DEL,t))
        after = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
        before_num = len(before.dumped_flows)
        after_num = len(after.dumped_flows)

        assert before_num > 2
        assert after_num == before_num-1 or after_num == before_num-2
        if after_num == before_num-2:
            return True
        else:
            return False

class SwitchDesc(object):
    def __init__(self,name,ports):
        self.name = name
        self.ports = ports

    def __str__(self):
        return name

class Command(object):
    def __init__(self,type,flowdesc=None,strict=False, dump_removeStatistics=False):
        self.type = type
        self.flowdesc = flowdesc
        self.dump_removeStatistics = dump_removeStatistics
        self.strict = strict

    def __str__(self):
        return '[' + str(Cmd.keys()[self.type]) + ', ' + str(self.flowdesc) + ((', strict=' + str(self.strict)) if self.strict else '') + ((', dump_removeStatistics=' + str(self.dump_removeStatistics)) if self.dump_removeStatistics else '') + ']'

class CommandResult(object):
    def __init__(self,type):
        self.type = type
        self.traced_rule = None
        self.traced_actions = None
        self.dumped_flows = []
        self.xid = None
        self.affected_flows = []
        self.overlaps = None
        pass

class OvsSwitch(object):
    def __init__(self,switchdesc):
        self.switchdesc = switchdesc
        pass

    def executeCommand(self,cmd):
        funcs = {Cmd.CREATE : self._create,
                 Cmd.RESET : self._reset,
                 Cmd.CLEAR : self._clear,
                 Cmd.TRACE : self._trace,
                 Cmd.DUMP : self._dump,
                 Cmd.OF_ADD : self._of_add,
                 Cmd.OF_DEL : self._of_del,
                 Cmd.OF_MOD : self._of_mod,
                 Cmd.OF_BAR : self._of_bar
        }
        return funcs[cmd.type](cmd)

    def _create(self,cmd):
        run_cmdline_string('ovs-vsctl add-br '+self.switchdesc.name)
        for i in xrange(1,self.switchdesc.ports,1):
            run_cmdline_string('ovs-vsctl add-port '+self.switchdesc.name+' '+self.switchdesc.name+'p'+str(i))
            run_cmdline_string('ovs-ofctl mod-port '+self.switchdesc.name+' '+self.switchdesc.name+'p'+str(i)+' up')
        return CommandResult(cmd.type)

    def _reset(self,cmd):
        try:
            run_cmdline_string('ovs-vsctl del-br '+self.switchdesc.name, noerr=False)
        except subprocess.CalledProcessError:
            pass
        self._create(cmd)
        return CommandResult(cmd.type)

    def _clear(self,cmd):
        run_cmdline_string('ovs-ofctl del-flows '+self.switchdesc.name)
        return CommandResult(cmd.type)

    def _trace(self,cmd):
        lines = run_cmdline_string('ovs-appctl ofproto/trace '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"')
        result = CommandResult(cmd.type)
        rule = None
        actions = None
        for l in lines:
            if rule is None and l.startswith("Rule: "):
                rule = l[6:]
            if actions is None and l.startswith("Datapath actions: "):
                actions = l[18:]
        result.traced_rule = rule
        result.traced_actions = actions
        return result

    def _dump(self,cmd):
        lines = run_cmdline_string('ovs-ofctl dump-flows '+self.switchdesc.name)
        result = CommandResult(cmd.type)
        assert len(lines) > 0;

        iterlines = iter(lines)
        headerline = next(iterlines)
        LBRACE,RBRACE,EQUAL = map(pp.Suppress,'()=')
        hexint = pp.Combine( "0x" + pp.Word(pp.hexnums))
        header = ('NXST_FLOW reply ' + LBRACE + 'xid' + EQUAL + hexint("xid"))
        parsed_header = header.parseString(headerline)

        result.xid = parsed_header.xid
        # We skipped the first element already
        for l in iterlines:
            flow = FlowDescription(l)
            if cmd.dump_removeStatistics:
                del flow.fields['cookie']
                del flow.fields['duration']
                del flow.fields['n_packets']
                del flow.fields['n_bytes']
                del flow.fields['idle_age']
            result.dumped_flows.append(flow)
        return result

    def _of_add(self,cmd):
        lines = run_cmdline_string('ovs-ofctl add-flow '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"',noerr=True)
        result = CommandResult(cmd.type)
        if len(lines) > 0:
            l = lines[0].strip()
            if l.startswith('OFPT_ERROR') and l.endswith('OFPFMFC_OVERLAP'):
                result.overlaps = True
        return result

    def _of_del(self,cmd):
        f = FlowDescription(str(cmd.flowdesc))
        f.actions = None
        if cmd.strict:
            run_cmdline_string('ovs-ofctl --strict del-flows '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"')
        else:
            del f.fields['priority']
            run_cmdline_string('ovs-ofctl del-flows '+self.switchdesc.name+' "'+str(f)+'"')
        return CommandResult(cmd.type)

    def _of_mod(self,cmd):
        if cmd.strict:
            lines = run_cmdline_string('ovs-ofctl --strict mod-flows '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"',noerr=True)
        else:
            f = FlowDescription(cmd.flowdesc)
            del f.fields['priority']
            lines = run_cmdline_string('ovs-ofctl mod-flows '+self.switchdesc.name+' "'+str(f)+'"',noerror=True)
        result = CommandResult(cmd.type)
        if len(lines) > 0:
            l = lines[0].strip()
            if l.startswith('OFPT_ERROR') and l.endswith('OFPFMFC_OVERLAP'):
                result.overlaps = True
        return result

    def _of_bar(self,cmd):
        # already done automatically
        return CommandResult(cmd.type)

class KvSwitchProxy(object):
    def __init__(self):
        pass

class PoxSwitchProxy(object):
    def __init__(self):
        pass

class FlowDescription(object):
    def __init__(self,s):
        # print s
        s = s.strip()
        # Parse string to flow description object
        # General definitions
        LBRACE,RBRACE,COMMA,EQUAL,COLON = map(pp.Suppress,'(),=:')
        WSPACE = pp.Suppress(pp.ZeroOrMore(pp.White()))
        identifier = pp.Word(pp.alphas + "_", pp.alphanums + "_")
        value = pp.Word(pp.printables.translate(None, ',='))
        integer = pp.Word(pp.nums)
        hexint = pp.Combine( "0x" + pp.Word(pp.hexnums))
        # hexint.setParseAction(lambda s,l,t: [ int(t[0],base=16) ])

        # Generic parsing of fields, excluding "actions" field
        field_key = identifier
        field_value = value
        field_entry = pp.Group(field_key + pp.Optional(EQUAL + field_value))
        fields = pp.Dict(field_entry + pp.ZeroOrMore(WSPACE + COMMA + WSPACE + field_entry))

        # Parsing of "actions" field
        action_args_generic = pp.Word(pp.printables.translate(None, ',()'))
        action_args_func = pp.Word(pp.printables.translate(None, '()'))
        action_entry_generic = pp.Group((identifier|integer) + pp.Optional(action_args_generic))
        action_entry_func = pp.Group(identifier + pp.Combine('(' + pp.Optional(action_args_func) + ')'))
        action_entry = action_entry_func | action_entry_generic

        actions = pp.Group(pp.Suppress('actions=') + pp.Dict(action_entry + pp.ZeroOrMore(WSPACE + COMMA + WSPACE + action_entry)))

        flowdesc_parser = fields("fields") + pp.Optional(WSPACE + actions("actions"))

        parsed = flowdesc_parser.parseString(s)
        # print parsed.dump()

        # Store
        self.fields = OrderedDict([(i[0],(None if len(i) < 2 else i[1])) for i in parsed.fields.asList()])
        if 'actions' in parsed:
            self.actions = OrderedDict([(i[0],(None if len(i) < 2 else i[1])) for i in parsed.actions.asList()])
        else:
            if 'actions' in self.fields.keys():
                self.actions = OrderedDict()
                self.actions['actions'] = self.fields['actions']
                del self.fields['actions']
            else:
                self.actions = None
        # Test
        #assert s == repr(self)
        # print repr(self)

    def __str__(self):
        return ', '.join([(k if v is None else k+'='+v) for k,v in self.fields.iteritems()]) + ('' if self.actions is None else ' actions='+','.join([(k if v is None else k+''+v) for k,v in self.actions.iteritems()]))

    def __repr__(self):
        return str(self.__class__.__name__) + '(\'' + str(self) + '\')'

    def __eq__(self, other):
        return (isinstance(other, self.__class__)
            and (dict(self.fields) == dict(other.fields)) and self.actions == other.actions)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        # Hash a canonical representation of the flow description
        mydict = dict(self.fields)
        mydict['actions'] = hash(frozenset(self.actions.items()))
        return hash(frozenset(mydict.items()))

# Helper functionality

def run_cmdline(args, input=None, chdir='.', nowait=False, noerr=False):
    # my_env = os.environ.copy()
    # print "$ " + " ".join(map(str,args))
    p = subprocess.Popen(args, close_fds=True, cwd=chdir, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    if nowait == True:
        return []
    else:
        if input is not None:
            output, unused_err = p.communicate(input);
        else:
            output, unused_err = p.communicate();
        if output is not None:
            lines = output.splitlines()
        else:
            lines = []
        retval = p.wait()
        if retval != 0 and not noerr:
            error = subprocess.CalledProcessError(retval, args, output)
            print "\n".join(map(str,lines))
            raise error
        # print "\n".join(map(str,lines))
        return lines

def run_cmdline_string(cmdline, *args, **kwargs):
    cmd = shlex.split(cmdline);
    return run_cmdline(cmd, *args, **kwargs);

if __name__ == "__main__":
    app = MainApp()
    app.run();