#!/usr/bin/env python
import sys
import os
import re
import subprocess
import shlex
import pyparsing as pp
from collections import OrderedDict
import itertools
import datetime, time
import functools
import pprint
from email.utils import COMMASPACE

# sys.path.append(os.path.join(os.path.dirname(__file__), "pox"))
# import pox.openflow.libopenflow_01 as of
# import pox.openflow.flow_table

# For type hints/annotations see: http://pydev.org/manual_adv_type_hints.html

# This enum adapted from: http://stackoverflow.com/a/1695250/202504
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
        sw = OvsSwitch(SwitchDesc('br0',10))
        sw.executeCommand(Command(Cmd.RESET))
        sw2 = OvsSwitch(SwitchDesc('br1',10))
        sw2.executeCommand(Command(Cmd.RESET))

        comparator = FlowComparator(sw2)

        testcases = []

        # Some regular testcases to test the program:

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
                                  Command(Cmd.CLEAR), # command A
                                  Command(Cmd.CLEAR), # command B
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


        # Autogenerate testcases by trying all combinations
        #
        # Notes:
        # - Always use 'output:x' instad of just 'x' in action lists.
        # - For IP addresses: Always use canonical representations, i.e. use 10.0.0.0/8 instead of 10.0.1.0/8
        #   -> Check e.g. here if necessary: http://jodies.de/ipcalc
        #

        command_list = [
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.0.0')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.0.1')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.1.0')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.2.0')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.1.0.0')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=0 actions=drop')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.1 actions=output:1')),
#             Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,in_port=ANY,vlan_tci=0x0000,dl_src=00:00:00:00:00:00,dl_dst=00:00:00:00:00:00,nw_src=0.0.0.0,nw_dst=10.0.0.1,nw_tos=0,nw_ecn=0,nw_ttl=0,tp_src=0,tp_dst=0,tcp_flags=0, actions=output:1')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/8 actions=output:2')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/24 actions=output:3')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.1.0/24 actions=output:4')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.2.0/24 actions=output:5')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.1.0.0/16 actions=output:6')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/16 actions=output:7')),
        ]
        initials_list = [
            [Command(Cmd.OF_ADD,FlowDescription('table=0, priority=0, tcp, actions=drop'))],
            [Command(Cmd.OF_ADD,FlowDescription('table=0, priority=0, tcp, actions=drop')),Command(Cmd.OF_ADD,FlowDescription('table=0, priority=10, tcp actions=drop'))],
            [Command(Cmd.OF_ADD,FlowDescription('table=0, priority=10, tcp, actions=drop'))],
            [Command(Cmd.OF_ADD,FlowDescription('table=0, priority=0, tcp, actions=drop')),Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/24 actions=output:8'))],
            [Command(Cmd.OF_ADD,FlowDescription('table=0, priority=0, tcp, actions=drop')),Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.1 actions=output:9'))],
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
        total = len(self.commands)*(len(self.commands)+1)/2*len(self.initials)
        caseno = 0
        passed = 0
        failed_imprecise = 0
        failed_unsound = 0
        failed = 0
        na = 0
        debug_cases = None #[22] # TODO JM: Debug code, remove
        print 'Running a total of {0} testcases'.format(total)
        for i in self.initials:
            for a,b in itertools.combinations_with_replacement(self.commands,2):
                # (n+r-1)! / r! / (n-1)!, with r=2
                # (n+1)! / 2 / (n-1)! = 1/2 * n(n+1)
                caseno += 1
                if debug_cases is None or caseno in debug_cases: # TODO JM: Debug code, remove
                    print str(caseno) + '/' +str(total) + ':',
                    tc = CommutativityTestCase(self.switch,a,b,i)
                    testcases.append(tc)
                    tc.expected = self.predictor.predict(tc)
                    result,info_str = tc.evaluate()
                    tc.result = result
                    tc.info_str = info_str
                    if result is True:
                        passed += 1
                        print 'Pass. ' + info_str
                    elif result is False:
                        failed += 1
                        if tc.expected == False:
                            # it commuted although we did not expect it to
                            failed_imprecise += 1
                            print 'Fail (impreciseness). ' + info_str
                            print str(tc)
                        else:
                            failed_unsound += 1
                            print 'Fail (unsoundness). ' + info_str
                            print str(tc)
                    else:
                        na += 1
                        print 'N/A. ' + info_str
#                         print str(tc)
        print 'Passed: {0}, Failed: {1} (imprecise: {2}, unsound: {3}), n/a: {4} , Total: {5}'.format(passed,failed,failed_imprecise,failed_unsound,na,total)
        assert total == len(testcases) 


class CommutativityPredictor(object):
    def __init__(self,switch,comparator):
        """Create object
        :type switch: OvsSwitch
        :type comparator : FlowComparator
        """
        self.switch = switch
        self.comparator = comparator

    def predict(self,testcase):
        """Apply commutativity rules
        :type testcase: CommutativityTestCase
        """
        testcase.simulate()
        initial = testcase.initial
        
        # order by enum to reduce number of cases
        x = testcase.a
        y = testcase.b
        ': :type x: Command'
        ': :type y: Command'
        
        xy_x = testcase.first_a
        xy_y = testcase.first_b
        xy_dump = testcase.first_dump
        yx_x = testcase.second_a
        yx_y = testcase.second_b
        yx_dump = testcase.second_dump
        ': :type xy_x: CommandResult'
        ': :type xy_y: CommandResult'
        ': :type xy_dump: CommandResult'
        ': :type yx_x: CommandResult'
        ': :type yx_y: CommandResult'
        ': :type yx_dump: CommandResult'
        
        if testcase.a > testcase.b:
            x = testcase.b
            y = testcase.a
            yx_y = testcase.first_a
            yx_x = testcase.first_b
            yx_dump = testcase.first_dump
            xy_y = testcase.second_a
            xy_x = testcase.second_b
            xy_dump = testcase.second_dump

        # RESET:
        #  - del(*) : <list of deleted flows>
        
        # add return values to results
        
        all_results = set()
        all_results.add(xy_x)
        all_results.add(xy_y)
        all_results.add(yx_x)
        all_results.add(yx_y)

        # store all logical return values so we don't need to calculate them more than once
        for r in all_results:
            r.update_return_value(self.comparator)
            

        # Determining the rules:
        # - Use the actual return values to see which flows were actually touched
        # - Compare this with the "other" command to see if:
        #   * some of the same rules were touched
        #   * some of the same rules could be touched
        
        # Wildcard examples:
        # - 10.x.x.x
        # - 10.0.x.x
        # - 10.0.0.x
        # - 10.0.0.1
        # - 20.x.x.x
        
        # Two commands may not commute in any of the cases:
        # - a subset b
        # - b subset a
        # - a equals b
        # - a intersects b
        #
        
        # Example in the case of trace/modify:
        #
        # - Table:
        #   Prio Flow       Action
        #   5    10.x.x.x   a1
        #   0    x.x.x.x    drop
        #
        # - Trace:  10.0.0.1
        #    -> Result = (5, 10.x.x.x; a1) : matched flow
        # - Modify: 10.x.x.x  a2
        #    -> Result = (5, 10.x.x.x; a2) : modified flows
        # 
        # -> Rule: Same flows affected, different action, thus does NOT commute
        #
        #
        
        # Example in the case of add/trace:
        # - Table:
        #   Prio Flow       Action
        #   5    10.x.x.x   a1
        #   0    x.x.x.x    drop
        #
        # - Trace:  10.0.0.1
        #    -> Result = (5, 10.x.x.x; a1) : matched flow
        # - Add: 5,10.0.x.x  a2
        #    -> Result = (5, 10.0.x.x; a2) : added flows
        #
        # Notice the general pattern:
        #  - Trace can not affect add.
        #  - Add can affect trace: A different rule would be selected if the 
        #    trace was executed *after* the add vs. *before* the add.
        #
        #  1. Add/Trace:
        #     - Trace matches the added rule after it's added -> no commute
        #     - Trace matches a different rule because of the add -> cannot happen
        #     - Trace matches the same rule regardless of the add -> commutes
        #  2. Trace/add: 
        #     - If we were to add the new rule before, the trace would match this new rule instead -> no commute
        #     - If we were to add the new rule before, the trace would match some other rule instead -> cannot happen
        #     - If we were to add the new rule before, the trace would still match the same rule -> commutes
        #
        # Commutativity rules if we are allowed to look at results explicitly:
        #
        #  1) add(p1,k1,a1)/<R1>   2) trace(k2)/<R2>
        #     - Commutes, if:
        #       R2 != R1
        #     - (ignoring counters):
        #       R2 != R1 or R2.a == R1.a
        #       
        #  1) trace(k1)/<R1>    2) add(p2,k2,a2)/<R2>
        #     - Does not commute, if:
        #       p2 >= R1.p and k1 in R2.k
        #     - Commutes, if:
        #       p2 < R1.p or k1 not in R2.k
        #                              k2
        #     - (ignoring counters):
        #       p2 < R1.p or k1 not in k2 or R1.a == R2.a
        #                                            a2
        #
        # Combining both sequences gives the final rule.
        #    trace(k1)/<R1>   add(p2,k2,a2)/<R2>
        #     
        # Commutes if:
        #     (R1 != R2 or R1.a == R2.a) and (p2 < R1.p or k1 not in k2 or R1.a == R2.a)
        #  -> (R1 != R2                  and (p2 < R1.p or k1 not in k2)) or R1.a == R2.a
        #
        #  -> (R1 != (p2,k2,a2)          and (p2 < R1.p or k1 not in k2)) or R1.a == a2
        #
        #
        # Verify using an example:
        #
        # - Table:
        #   Prio Flow       Action
        #   0    x.x.x.x    drop
        #
        # - trace(10.0.0.1)/<0,x.x.x.x,drop>   add(5,10.x.x.x,a2)/<>
        #   eval: (R1 != (p2,k2,a2)          and (p2 < R1.p or k1 not in k2)) or R1.a == a2
        #         (true                      and (false     or false       )) or false
        #         FALSE
        #
        # - add(5,10.x.x.x,a1)/<>   trace(10.0.0.1)/<5,10.x.x.x,a1>
        #   eval: (R2 != (p1,k1,a1)          and (p1 < R2.p or k2 not in k1)) or R2.a == a1
        #         (false                     and (false     or false       )) or true
        # 
        #   PROBLEM!!! This is not correct...!
        #
        # Either we restrict the rule to not consider the "R2.a == a1" clause,
        # or we add information about the previous state to the add() return 
        # value.
        #
        # Need a way to determine what would have matched every packet matching 
        # the newly added flow had the add not been executed.
        # Solution: Return all rules that are less specific than the newly
        #           added rule as the return value.
        #
        # i.e. we define add(p,k,a)/<R>, where R is the set of all rules in the
        # flow table that are a superset of k.
        #
        # Then, can redo example:
        # - add(5,10.x.x.x,a1)/<[0,x.x.x.x,drop]>   trace(10.0.0.1)/<5,10.x.x.x,a1>
        #
        #   matching up actions: R2.a == a1 now becomes:
        #    -> select(k1,R1).a == R2.a
        #
        #   eval: (R2 != (p1,k1,a1)          and (p1 < R2.p or k2 not in k1)) or select(k1,R1).a == R2.a
        #         (false                     and (false     or false       )) or false
        # 
        # But what if we have:
        # - Table:
        #   Prio Flow       Action
        #   0    x.x.x.x    drop
        #   5    10.0.x.x   a1
        #   5    10.1.x.x   a2
        #
        # Return values?
        #
        # - add(5,10.x.x.x,a3)/<[5,10.0.x.x,a1;5,10.1.x.x,a2;0,x.x.x.x,drop]>
        #   trace(10.0.0.1)/<5,10.0.x.x,a1>
        #   -> Commutes!
        #
        # - add(5,10.x.x.x,a3)/<[5,10.0.x.x,a1;5,10.1.x.x,a2;0,x.x.x.x,drop]>
        #   trace(10.3.0.1)/<5,10.x.x.x,a3>
        #   -> Does not commute!
        #
        #
        # Thus the final rule is: 
        #   
        #   add(pa,ka,aa)/<Ra>  trace(kt)/<Rt>
        #
        # Not considering statistics, and using multivalued return value:
        # - (Rt != (pa,ka,aa) and (pa < Rt.p or kt not in ka)) or select(kt,Ra).a == Rt.a
        # 
        # Considering statistics, no return value for add() needed:
        # -  Rt != (pa,ka,aa) and (pa < Rt.p or kt not in ka)
        #
        # Unused old rule (just slightly different, but wrong)
        #   write(p1,k1,a1)/a_old1
        #   read(h2)/<p2,a2>
        #   Commutes if: not matches(h2,k1) or p2 > p1 or a1=a_old1
        #
        

        if x.type in (Cmd.RESET, Cmd.CLEAR):
            if y.type in (Cmd.RESET, Cmd.CLEAR):
                return True  #always commutes
        
            if y.type == Cmd.TRACE:
                return None
                
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
                #   add(pa,ka,aa)/<Ra>  trace(kt)/<Rt>
                #
                # Not considering statistics, and using multivalued return value:
                # - (Rt != (pa,ka,aa) and (pa < Rt.p or kt not in ka)) or select(Rt.k,Ra).a == Rt.a
                # 
                # Considering statistics, no return value for add() needed:
                # -  Rt != (pa,ka,aa) and (pa < Rt.p or kt not in ka)
                
                # Rewritten:
                # Does NOT commute if:
                # (Rt == (pa,ka,aa) or (pa >= Rt.p and kt in ka)) and select(Rt.k,Ra).a != Rt.a
               
                
                # x is TRACE
                # y is ADD
                
                kt = x.flowdesc.get_match() # TRACE key
                
                pa_ka_aa = y.flowdesc
                pa = pa_ka_aa.get_priority() # ADD prio
                ka = pa_ka_aa.get_match() # ADD key
                aa = pa_ka_aa.get_actions() # ADD action
                
                Rt1 = xy_x.retval # Which rule did the TRACE use (case 1: ADD was not yet executed)
                Rt2 = yx_x.retval # Which rule did the TRACE use (case 2: ADD was already executed)
                Rt1a = Rt1.get_actions()
                Rt2a = Rt2.get_actions()
                Rt1p = Rt1.get_priority()
                Rt2p = Rt2.get_priority()
                Rt1k = Rt1.get_match()
                Rt2k = Rt2.get_match()
                
                Ra1 = xy_y.retval # Which rules did ADD override/hide that were previously there? (case 1)
                Ra2 = yx_y.retval # Which rules did ADD override/hide that were previously there? (case 2)
                
                s = self.comparator.is_subset(kt,ka) # is the TRACE key a subset of the ADD key? 
                t1 = self.comparator.select(kt,Ra1) # which rule would TRACE use from the overridden/hidden rules (case 1)
                t2 = self.comparator.select(kt,Ra2) # which rule would TRACE use from the overridden/hidden rules (case 2)
                u1 = t1.get_actions() # what would the corresponding action be (case 1)
                u2 = t2.get_actions() # what would the corresponding action be (case 2)
                
                
                # Case 1: TRACE->ADD. At the time of the check, TRACE was already executed but ADD not.
                xy_conflicts = ((Rt1 == pa_ka_aa) or (pa >= Rt1p and s)) and u1 != Rt1a
                
                #               the TRACE chose the ADD exactly
                #                                     the TRACE chose some other rule, but it would also match
                #                                     the ADD, and the ADD has higher priority
                #                                                            out of all the rules the ADD replaced
                
                # Case 2; ADD->TRACE. At the time of the check, ADD was already executed but TRACE was not.
                yx_conflicts = ((Rt2 == pa_ka_aa) or (pa >= Rt2p and s)) and u2 != Rt2a
                
                
                
                #
                # General pattern:
                # - Determine conflicts for both orders A->B and B->A
                #   - In each those orders determine conflict for both commands:
                #     - Here, ADD never conflicts
                #     - TRACE may conflict
                #
                # - Combine formulas with ORs. Here this results in 2 clauses, in the general case we will get 4.
                #
                
                # TRACE -> ADD
                xy_conflicts = (s and pa >= Rt1p and aa != Rt1a)
                # ADD -> TRACE
                yx_conflicts = (Rt2 == pa_ka_aa and u2 != Rt2a)
                
                xy_conflicts = (s and pa >= Rt1p and aa != Rt1a) or (Rt1 == pa_ka_aa and u1 != Rt1a)
                yx_conflicts = (s and pa >= Rt2p and aa != Rt2a) or (Rt2 == pa_ka_aa and u2 != Rt2a)
                
                
                
                # To be a valid specification, the rule has to produce the same output for each case. In reality,
                # only one of the cases will be available for checking.
                assert xy_conflicts == yx_conflicts
                return not xy_conflicts
        
            if y.type == Cmd.OF_DEL:
                if y.strict:
                    return None
                else:
                    return None
        
            if y.type == Cmd.OF_MOD:
                if y.strict:
                    return None
                else:
                    return None
        
#         if x.type == Cmd.OF_ADD:
#             if x.strict:
#                 if y.type == Cmd.OF_ADD:
#                     return None
#         
#                 if y.type == Cmd.OF_DEL:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#         
#                 if y.type == Cmd.OF_MOD:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#             else:
#                 if y.type == Cmd.OF_ADD:
#                     return None
#         
#                 if y.type == Cmd.OF_DEL:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#         
#                 if y.type == Cmd.OF_MOD:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#         
#         if x.type == Cmd.OF_DEL:
#             if x.strict:
#                 if y.type == Cmd.OF_DEL:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#         
#                 if y.type == Cmd.OF_MOD:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#             else:
#                 if y.type == Cmd.OF_DEL:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#         
#                 if y.type == Cmd.OF_MOD:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#         
#         if x.type == Cmd.OF_MOD:
#             if x.strict:
#                 if y.type == Cmd.OF_MOD:
#                     if y.strict:
#                         return None
#                     else:
#                         return None
#             else:
#                 if y.type == Cmd.OF_MOD:
#                     if y.strict:
#                         return None
#                     else:
#                         return None

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
        self._simulate_done = False

    def simulate(self):
        """
        Execute both possible traces, store results
        """

        if not self._simulate_done:
            self.switch.executeCommand(Command(Cmd.CLEAR))
            for cmd in self.initial:
                self.switch.executeCommand(cmd)
    
            # print "Running a->b"
            self.first_a = self.switch.executeCommand(self.a,return_affected=True)
            self.first_b = self.switch.executeCommand(self.b,return_affected=True)
    
            self.first_dump = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
    
            self.switch.executeCommand(Command(Cmd.CLEAR))
            for cmd in self.initial:
                self.switch.executeCommand(cmd)
    
            # print "Running b->a"
            self.second_b = self.switch.executeCommand(self.b,return_affected=True)
            self.second_a = self.switch.executeCommand(self.a,return_affected=True)
    
            self.second_dump = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
    
            self._simulate_done = True

    def evaluate(self):
        """
        Check commutativity, compare with expected testcase
        """
        if not self._simulate_done:
            self.simulate()

        # print "Starting testcase"

        # Commutativity:
        # - All traces execute the same actions. Here we can do direct string comparison, as the list of actions is ordered.
        # - The flow tables are the same afterwards

        # Preliminary
        commutes = True

        if self.a.type == Cmd.TRACE:
            # compare first_a with second_a
            if self.first_a.traced_actions != self.second_a.traced_actions:
                commutes = False
                if self.expected != False:
#                     print 'Actions for a not the same: '+str(self.first_a.traced_actions)+' vs. '+str(self.second_a.traced_actions)
                    pass

        if self.b.type == Cmd.TRACE:
            # compare first_b with second_b
            if self.first_b.traced_actions != self.second_b.traced_actions:
                commutes = False
                if self.expected != False:
#                     print 'Actions for b not the same: '+str(self.first_b.traced_actions)+' vs. '+str(self.second_b.traced_actions)
                    pass
                
        #compare first_dump to second_dump
        first_set = set(self.first_dump.dumped_flows)
        second_set = set(self.second_dump.dumped_flows)
        if not first_set == second_set:
            commutes = False
            # print "Flow tables not the same"
            # print "In first but not second:"
            # print list(first_set.difference(second_set))
            # print "In second but not first:"
            # print list(second_set.difference(first_set))

        # print "Done with testcase"
        info_str = ('commutes.' if commutes else 'does not commute.') + ' Rules added/removed: ' \
        '(' + '+'+str(len(self.first_a.added_flows))+'/-'+str(len(self.first_a.removed_flows))+', '+'+'+str(len(self.first_b.added_flows))+'/-'+str(len(self.first_b.removed_flows))+')' + ' vs.' \
        '(' + '+'+str(len(self.second_a.added_flows))+'/-'+str(len(self.second_a.removed_flows))+', '+'+'+str(len(self.second_b.added_flows))+'/-'+str(len(self.second_b.removed_flows))+')'

        if self.expected is not None:
            if commutes == self.expected:
                return (True,info_str)
            else:
                return (False,info_str)
        else:
            return (None,info_str)

    def __str__(self):
        initial_str = ', '.join([str(i) for i in self.initial])
        return '(\n\t' + str(self.a) + ',\n\t' + str(self.b) + ',\n\tinitial=' + initial_str + ',\n\texpected=' + str(self.expected) + '\n)'

class FlowComparator(object):
    def __init__(self,switch):
        self.switch = switch

    def _reset(self):
        self.switch.executeCommand(Command(Cmd.CLEAR))

    def select(self,s,table):
        """Match a flow s to the single closest flow entry in a flow table. 
        Note that in case there are overlapping entries, this will fail with
        an assertion failure. In a real switch, the behaviour would be implementation
        dependent.
        :type s: FlowDescription
        :type t: list[FlowDescription]
        :rtype: FlowDescription
        """
        self._reset()
        for t in table:
            ': :type t: FlowDescription'
            t.fields['check_overlap'] = None #enables overlap checking (key has no value, thus None)
            cmd_ret = self.switch.executeCommand(Command(Cmd.OF_ADD,t))
            ': :type cmd_ret: CommandResult'
            assert not cmd_ret.overlap_error
        cmd_ret = self.switch.executeCommand(Command(Cmd.TRACE,s))
        ': :type cmd_ret: CommandResult'
        selected_flow = FlowDescription(cmd_ret.traced_rule)
        selected_flow.set_actions(cmd_ret.traced_actions)
        return selected_flow

    def is_intersection_nonempty(self,s,t,use_priorities=False):
        """Do s and t intersect?
        :type s: FlowDescription
        :type t: FlowDescription
        :type use_priorities: bool
        :rtype: bool
        """
        # is the intersection(s,t) non-empty?
        # Note: Priorities ARE checked here!
        self._reset()
        s.actions = OrderedDict([('1',None)])
        t.actions = OrderedDict([('2',None)])
        if not use_priorities:
            # set priorities to be the same
            s.set_priority(5)
            t.set_priority(5)
        result_s = self.switch.executeCommand(Command(Cmd.OF_ADD,s))
        t.fields['check_overlap'] = None #enables overlap checking (key has no value, thus None)
        result_t = self.switch.executeCommand(Command(Cmd.OF_ADD,t))
        if result_t.overlap_error is True:
            return True
        else:
            return False
        
    def subset_set(self,s,flow_set):
        """Return all flows that are a subset of s
        """
        subset_flows = set()
        for t in flow_set:
            if self.is_subset(s, t):
                subset_flows.add(t)
        return subset_flows
    
    def intersecting_set(self,s,flow_set):
        """Return all flows that overlap with the given mask
        """
        intersecting_flows = set()
        for t in flow_set:
            if self.is_intersection_nonempty(t, s):
                intersecting_flows.add(t)
        return intersecting_flows
    
    def superset_set(self,s,flow_set):
        """Return all flows that are a superset of s (s is a subset of)
        """
        superset_flows = set()
        for t in flow_set:
            if self.is_subset(s, t):
                superset_flows.add(t)
        return superset_flows

    def is_subset(self,s,t):
        """Do all packets matching s also match t?
        :type s: FlowDescription
        :type t: FlowDescription
        :rtype: bool
        """
        # is s a subset of t?
        # TODO: this can be done much faster (without simulation)
        # Note: Priorities are NOT checked here!
        s_copy = s.copy()
        t_copy = t.copy()
        self._reset()
        s_copy.actions = OrderedDict([('1',None)])
        t_copy.actions = OrderedDict([('2',None)])
        result_t = self.switch.executeCommand(Command(Cmd.OF_ADD,t_copy))
        result_s = self.switch.executeCommand(Command(Cmd.OF_ADD,s_copy))
        before = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
        result = self.switch.executeCommand(Command(Cmd.OF_DEL,t_copy))
        after = self.switch.executeCommand(Command(Cmd.DUMP,dump_removeStatistics=True))
        before_num = len(before.dumped_flows)
        after_num = len(after.dumped_flows)

        if before_num == 1:
            # s overwrote t
            return True
        else:
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
        return self.name

class Command(object):
    def __init__(self,cmd_type,flowdesc=None,strict=False, dump_removeStatistics=False):
        self.type = cmd_type
        self.flowdesc = flowdesc
        ': :type : FlowDescription'
        self.dump_removeStatistics = dump_removeStatistics
        ': :type : bool'
        self.strict = strict
        ': :type : bool'

    def __str__(self):
        return '[' + str(Cmd.keys()[self.type]) + ', ' + str(self.flowdesc) + ((', strict=' + str(self.strict)) if self.strict else '') + ((', dump_removeStatistics=' + str(self.dump_removeStatistics)) if self.dump_removeStatistics else '') + ']'

class CommandResult(object):
    def __init__(self,cmd):
        """Create object
        :type cmd: Command
        """
        # type of command that was executed
        self.cmd = cmd
        self.type = self.cmd.type
        # for Cmd.TRACE: Which rule was read and what actions does that rule have
        self.traced_rule = None
        self.traced_actions = None
        # for Cmd.DUMP: All flows in the table
        self.dumped_flows = None
        # Transaction ID
        self.xid = None
        # flows before/after
        self.before_set = None
        self.after_set = None
        # which flows were added/removed/overwritten
        self.added_flows = None
        self.removed_flows = None
        self.overwritten_flows = None
        # Union of added/removed/affected flows
        self.affected_flows = None
        # was an OFPFMFC_OVERLAP error returned?
        self.overlap_error = None
        self.retval = None
        
    def update_return_value(self,comparator):
        self.retval = self._calc_return_value(comparator)
        
    def _calc_return_value(self,comparator):
        funcs = {Cmd.CREATE : self._retval_create,
                 Cmd.RESET : self._retval_reset,
                 Cmd.CLEAR : self._retval_clear,
                 Cmd.TRACE : self._retval_trace,
                 Cmd.DUMP : self._retval_dump,
                 Cmd.OF_ADD : self._retval_of_add,
                 Cmd.OF_DEL : self._retval_of_del,
                 Cmd.OF_MOD : self._retval_of_mod,
                 Cmd.OF_BAR : self._retval_of_bar
        }
        return funcs[self.type](comparator)
        
    def _retval_create(self,comparator):
        return None
    def _retval_reset(self,comparator):
        # Return all rules that were deleted by the reset.
        return self.removed_flows
    def _retval_clear(self,comparator):
        # Return all rules that were deleted by the reset.
        return self.removed_flows
    def _retval_trace(self,comparator):
        # Return the traced rule. NOTE: The rare case of multiple equally matching rules is ignored.
        result = FlowDescription(self.traced_rule)
        result.set_actions(self.traced_actions)
        result.remove_statistics()
        return result
    def _retval_dump(self,comparator):
        # Return all rules
        return self.before_set
    def _retval_of_add(self,comparator):
        ': :type comparator: FlowComparator'
        # Return all rules in the flow table that are a superset of s, if none of
        # them have higher priority than s. (If any of them had higher priority,
        # then the added rule would not make any kind of difference.
        s = FlowDescription(str(self.cmd.flowdesc))
        s_prio = s.get_priority()
        s.remove_statistics()
        s.remove_priority()
        s.remove_actions()
        superset_flows = comparator.superset_set(s, self.before_set)
        for t in superset_flows:
            t_prio = t.get_priority()
            if t_prio > s_prio:
                return set() # empty set
        return superset_flows

    def _retval_of_del(self,comparator):
        # Return all rules that were removed by the deletion.
        return self.removed_flows
    def _retval_of_mod(self,comparator):
        # Return all rules that have a different action after modification
        return self.affected_flows        
    def _retval_of_bar(self,comparator):
        # No return value
        return None

class OvsSwitch(object):
    def __init__(self,switchdesc):
        self.switchdesc = switchdesc
        pass

    def executeCommand(self,cmd,return_affected=False):
        """Execute a command.
        :type cmd: Command
        :type return_affected: bool
        :rtype: CommandResult
        """
        if return_affected and (cmd not in (Cmd.TRACE, Cmd.DUMP, Cmd.OF_BAR)):
            # we will not get information about the affected rules in the result
            before = self._execute(Command(Cmd.DUMP,dump_removeStatistics=True))
            result = self._execute(cmd)
            after = self._execute(Command(Cmd.DUMP,dump_removeStatistics=True))

            #compute set of affected rules in the before set
            result.before_set = set(before.dumped_flows)
            result.after_set = set(after.dumped_flows)

            result.removed_flows = result.before_set.difference(result.after_set)
            result.added_flows = result.after_set.difference(result.before_set)
            result.affected_flows = result.before_set.symmetric_difference(result.after_set)
            
            # OF_ADD is a special case, as it may overwrite itself but we have no way to detect this with OVS (we could look at the 'duration' field but that is not guaranteed to work)
            if cmd == Cmd.OF_ADD and len(result.affected_flows) == 0:
                result.overwritten_flows.add(cmd.flowdesc)
                result.affected_flows.add(cmd.flowdesc)
              
            return result
        else:
            return self._execute(cmd)

    def _execute(self,cmd):
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
        return CommandResult(cmd)

    def _reset(self,cmd):
        try:
            run_cmdline_string('ovs-vsctl del-br '+self.switchdesc.name, noerr=False)
        except subprocess.CalledProcessError:
            pass
        self._create(cmd)
        return CommandResult(cmd)

    def _clear(self,cmd):
        run_cmdline_string('ovs-ofctl del-flows '+self.switchdesc.name)
        return CommandResult(cmd)

    def _trace(self,cmd):
        f = FlowDescription(str(cmd.flowdesc))
        f.remove_table()
        f.remove_actions()
        f.remove_priority()
        f.remove_statistics()
        lines = run_cmdline_string('ovs-appctl ofproto/trace '+self.switchdesc.name+' "'+str(f)+'"')
        result = CommandResult(cmd)
        rule = None
        actions = None
        for l in lines:
            if rule is None and l.startswith("Rule: "):
                rule = l[6:]
            if actions is None and l.startswith("OpenFlow actions="):
                actions = l[17:]
        result.traced_rule = rule
        result.traced_actions = actions
        return result

    def _dump(self,cmd):
        lines = run_cmdline_string('ovs-ofctl dump-flows '+self.switchdesc.name)
        result = CommandResult(cmd)
        result.dumped_flows = []
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
                flow.remove_statistics()
            result.dumped_flows.append(flow)
        return result

    def _of_add(self,cmd):
        # TODO: Handle OFPFMFC_ALL_TABLES_FULL case
        lines = run_cmdline_string('ovs-ofctl add-flow '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"',noerr=True)
        result = CommandResult(cmd)
        if len(lines) > 0:
            l = lines[0].strip()
            if l.startswith('OFPT_ERROR') and l.endswith('OFPFMFC_OVERLAP'):
                result.overlap_error = True
            if l.find('must specify an action') != -1:
                raise Exception(lines)
        return result

    def _of_del(self,cmd):
        f = FlowDescription(str(cmd.flowdesc))
        f.actions = None
        if cmd.strict:
            run_cmdline_string('ovs-ofctl --strict del-flows '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"')
        else:
            f.remove_priority()
            run_cmdline_string('ovs-ofctl del-flows '+self.switchdesc.name+' "'+str(f)+'"')
        return CommandResult(cmd)

    def _of_mod(self,cmd):
        if cmd.strict:
            lines = run_cmdline_string('ovs-ofctl --strict mod-flows '+self.switchdesc.name+' "'+str(cmd.flowdesc)+'"',noerr=True)
        else:
            f = FlowDescription(cmd.flowdesc)
            f.remove_priority()
            lines = run_cmdline_string('ovs-ofctl mod-flows '+self.switchdesc.name+' "'+str(f)+'"',noerror=True)
        result = CommandResult(cmd)
        if len(lines) > 0:
            l = lines[0].strip()
            if l.startswith('OFPT_ERROR') and l.endswith('OFPFMFC_OVERLAP'):
                result.overlaps = True
        return result

    def _of_bar(self,cmd):
        # already done automatically
        return CommandResult(cmd)

class KvSwitchProxy(object):
    def __init__(self):
        pass

class PoxSwitchProxy(object):
    def __init__(self):
        pass

class FlowDescription(object):
    def __init__(self,s):
        s = ' '.join(s.split())
#         print ' --------------------------'
#         print s
        # Parse string to flow description object
        # General definitions
        LBRACE,RBRACE,COMMA,EQUAL,COLON = map(pp.Suppress,'(),=:')
        WSPACE = pp.Suppress(pp.ZeroOrMore(pp.White()))
        SEPARATOR = pp.Suppress(pp.oneOf(['',' ',',',' ,',', ',' , ']))
        identifier = pp.Word(pp.alphas + "_", pp.alphanums + "_")
        value = pp.Word(pp.printables.translate(None, ',='))
        integer = pp.Word(pp.nums)
        hexint = pp.Combine( "0x" + pp.Word(pp.hexnums))
        # hexint.setParseAction(lambda s,loc,tok: [ int(tok[0],base=16) ])

        # Generic parsing of fields, excluding "actions" field
        field_key = identifier
        field_value = value
        field_entry = pp.Group(field_key + pp.Optional(EQUAL + field_value))
        fields = pp.Dict(field_entry + pp.ZeroOrMore(SEPARATOR + field_entry))

        flowdesc_parser = fields("fields")

        parsed = flowdesc_parser.parseString(s)
#         print parsed.dump()

        # Store
        self.fields = OrderedDict([(i[0],(None if len(i) < 2 else i[1])) for i in parsed.fields.asList()])
        if 'actions' in self.fields.keys():
            self.set_actions(self.fields['actions'])
            del self.fields['actions']
        else:
            self.actions = None
            
        # Test
        #assert s == repr(self)
#         print str(self)
    
    def remove_statistics(self):
        self.fields.pop('cookie',None)
        self.fields.pop('duration',None)
        self.fields.pop('n_packets',None)
        self.fields.pop('n_bytes',None)
        self.fields.pop('idle_age',None)
    
    def remove_priority(self):
        self.fields.pop('priority',None)
    
    def remove_actions(self):
        self.fields.pop('actions',None)
        self.actions = None
    
    def remove_table(self):
        self.fields.pop('table',None)
        
    def get_priority(self):
        """Parse 'priority' field and interpret it as an integer value
        :rtype: int
        """
        if 'priority' in self.fields:
            integer = pp.Word(pp.nums)
            priority = integer
             
            def _parse_priority(s,loc,tok):
                # Note: effectively the same as using return int(self.fields['priority']), but ignores whitespace
                assert len(tok) == 1
                return int(tok[0]) # unpack
 
            priority.setParseAction(_parse_priority)
            flowdesc_parser = priority("priority")
            parsed = flowdesc_parser.parseString(self.fields['priority'])
            return parsed.priority
        else:
            return None

    def get_duration(self):
        """Parse 'duration' field and interpret it as a datetime.timedelta value
        :rtype: datetime.timedelta
        """
        if 'duration' in self.fields:
            integer = pp.Word(pp.nums)
            seconds = integer
            milliseconds = integer
            duration = seconds("seconds") + pp.Optional(pp.Suppress('.') + milliseconds("milliseconds")) + pp.Suppress('s')

            def _parse_duration(s,loc,tok):
                assert len(tok) == 1 or len(tok) == 2
                if len(tok) == 2:
                    return datetime.timedelta(seconds=int(tok[0]), microseconds=1000*int(tok[1]))
                elif len(tok) == 1:
                    return datetime.timedelta(seconds=int(tok[0]))

            duration.setParseAction(_parse_duration)
            flowdesc_parser = duration("duration")
            parsed = flowdesc_parser.parseString(self.fields['duration'])
            print parsed.dump()
            dd = parsed.duration
            print dd
            return parsed.duration
        else:
            return None
        
    def get_actions(self):
        """Get the actions as a string
        :rtype: str
        """
        return ('' if self.actions is None else ','.join([(k if v is None else k+''+v) for k,v in self.actions.iteritems()]))
    
    def get_match(self):
        """Get a copy of this FlowDescription with stats, priority, actions removed.
        :rtype: FlowDescription
        """
        result = self.copy()
        result.remove_statistics()
        result.remove_priority()
        result.remove_actions()
        return result
        
    def set_priority(self,p):
        """Set 'priority' field to integer value p
        :type p: int
        """
        self.fields['priority'] = str(p)
    
    def set_duration(self,d):
        """Set 'duration' field to datetime.timedelta value d
        :type d: datetime.timedelta
        """
        self.fields['duration'] = '{0}s'.format(d.total_seconds())
    
    def set_actions(self,a):
        """Set actions.
        :type a: str
        """
        identifier = pp.Word(pp.alphas + "_", pp.alphanums + "_")
        integer = pp.Word(pp.nums)
        
        action_args_generic = pp.Word(pp.printables.translate(None, ',()'))
        action_args_func = pp.Word(pp.printables.translate(None, '()'))
        action_entry_generic = (identifier|integer) + pp.Optional(action_args_generic)
        action_entry_func = identifier + pp.Combine('(' + pp.Optional(action_args_func) + ')')
        action_entry = pp.Group(action_entry_func | action_entry_generic)

        actions = pp.Dict(action_entry + pp.ZeroOrMore(pp.Suppress(',') + action_entry))

        action_parser = actions("actions")

        parsed = action_parser.parseString(a)
        
        if 'actions' in parsed:
            self.actions = OrderedDict([(i[0],(None if len(i) < 2 else i[1])) for i in parsed.actions.asList()])
        else:
            self.actions = None

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
    
    def copy(self):
        return FlowDescription(self.__str__())

# Helper functionality

def run_cmdline(args, piped_input=None, chdir='.', nowait=False, noerr=False):
    """Run a command externally.
    """
    # my_env = os.environ.copy()
#     print "$ " + " ".join(map(str,args))
    p = subprocess.Popen(args, close_fds=True, cwd=chdir, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    if nowait == True:
        return []
    else:
        if piped_input is not None:
            output, unused_err = p.communicate(piped_input);
        else:
            output, unused_err = p.communicate();
        if output is not None:
            lines = output.splitlines()
        else:
            lines = []
        retval = p.wait()
        if retval != 0 and not noerr:
            error = subprocess.CalledProcessError(retval, args, output)
            print " ".join(map(str,args))
            print output
            raise error
#         print "\n".join(map(str,lines))
        return lines

def run_cmdline_string(cmdline, *args, **kwargs):
    cmd = shlex.split(cmdline);
    return run_cmdline(cmd, *args, **kwargs);

if __name__ == "__main__":
    app = MainApp()
    app.run();