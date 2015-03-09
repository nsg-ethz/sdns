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

# sys.path.append(os.path.join(os.path.dirname(__file__), "pox"))
# import pox.openflow.libopenflow_01 as of
# import pox.openflow.flow_table

# For type hints/annotations see: http://pydev.org/manual_adv_type_hints.html

#
# TODO JM: Add support for out_port matching for DELETE and DELETE_STRICT?
#

# This enum adapted from: http://stackoverflow.com/a/1695250/202504
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    key_names = reverse
    @classmethod
    def keys(cls):
       return key_names
    enums['keys'] = keys
    @classmethod
    def values(cls):
       return enums
    enums['values'] = values
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
        # - Always use 'output:x' instead of just 'x' in action lists.
        # - For IP addresses: Always use canonical representations, i.e. use 10.0.0.0/8 instead of 10.0.1.0/8
        #   -> Check using ipcalc if necessary, e.g.: $ ipcalc 10.0.1.0/8 | grep Network
        #

        command_list = [
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.0.0')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.0.1')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.1.0')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.0.2.0')),
            Command(Cmd.TRACE,FlowDescription('tcp,nw_dst=10.1.0.0')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=0 actions=drop')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.1 actions=output:1')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/8 actions=output:2')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/24 actions=output:3')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.1.0/24 actions=output:4')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.2.0/24 actions=output:5')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.1.0.0/16 actions=output:6')),
            Command(Cmd.OF_ADD,FlowDescription('table=0, priority=5, tcp,nw_dst=10.0.0.0/16 actions=output:7')),
            Command(Cmd.OF_DEL,FlowDescription('table=0, tcp,nw_dst=10.0.0.1')),
            Command(Cmd.OF_DEL,FlowDescription('table=0, tcp,nw_dst=10.0.0.0/24')),
            Command(Cmd.OF_MOD,FlowDescription('table=0, tcp,nw_dst=10.0.0.1 actions=output:6')),
            Command(Cmd.OF_MOD,FlowDescription('table=0, tcp,nw_dst=10.0.0.0/24 actions=output:7')),
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
        total_permutations = len(self.commands)*(len(self.commands)+1)/2*len(self.initials)
        caseno = 0
        passed = 0
        failed_imprecise = 0
        failed_unsound = 0
        failed = 0
        na = 0
        skipped = 0
        total = 0
        
        valid_types = [Cmd.TRACE, Cmd.OF_ADD, Cmd.OF_DEL, Cmd.OF_MOD]
        
        valid_perms = []
        for i in itertools.combinations_with_replacement(self.commands,2):
          if i[0].type in valid_types and i[1].type in valid_types:
            total += 1
            valid_perms.append(i)
        
        total = total * len(self.initials)
        
        print 'Running a total of {0} testcases.'.format(total)
        debug_cases = None #[6] #[116] # TODO JM: Debug code, remove
        for i in self.initials:
            for a,b in valid_perms:
                # (n+r-1)! / r! / (n-1)!, with r=2
                # (n+1)! / 2 / (n-1)! = 1/2 * n(n+1)
                caseno += 1
                if debug_cases is None or caseno in debug_cases: # TODO JM: Debug code, remove
                    print str(caseno) + '/' +str(total) + ':',
                    tc = CommutativityTestCase(self.switch,a,b,i)
                    testcases.append(tc)
                    tc.expected = self.predictor.predict(tc)
                    if tc.expected is None:
                      if self.predictor.last_none_was_mod_as_add:
                        print 'Skipped MOD behaving as an ADD'
                        skipped += 1
                      else:
                        print 'Skipped (N/A)'
                        print tc
                        na += 1
                      continue
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
                        print str(tc)
        print 'Passed: {0}, Failed: {1} (imprecise: {2}, unsound: {3}), Skipped: {4}, N/A: {5}, Total testcases: {6}'.format(passed,failed,failed_imprecise,failed_unsound,skipped,na,total)
        print 'Done!'


class CommutativityPredictor(object):
    def __init__(self,switch,comparator):
        """Create object
        :type switch: OvsSwitch
        :type comparator : FlowComparator
        """
        self.switch = switch
        self.comparator = comparator
        self.last_none_was_mod_as_add = False

    def predict(self,testcase):
        """Apply commutativity rules
        :type testcase: CommutativityTestCase
        """
        self.last_none_was_mod_as_add = False
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
        
        if testcase.a.type > testcase.b.type or (
                                       testcase.a == testcase.b and 
                                       hasattr(testcase.b, 'strict') and testcase.b.strict and 
                                       hasattr(testcase.a, 'strict') and not testcase.a.strict):
            x = testcase.b
            y = testcase.a
            yx_y = testcase.first_a
            yx_x = testcase.first_b
            yx_dump = testcase.first_dump
            xy_y = testcase.second_a
            xy_x = testcase.second_b
            xy_dump = testcase.second_dump
        
        # add return values to results
        all_results = set()
        all_results.add(xy_x)
        all_results.add(xy_y)
        all_results.add(yx_x)
        all_results.add(yx_y)

        # store all logical return values so we don't need to calculate them more than once
        for r in all_results:
            r.update_return_value(self.comparator)
        
        # General tactic
        # --------------
        # - Determine conflicts for both orders A->B and B->A
        #   - In each those orders determine conflict for both commands:
        #     - Reorder first after second
        #     - Reorder second before first
        #
        # - Combine formulas with ORs (4 clauses)
        #
        # Terminology
        # -----------
        #  p=priority, k=key/match, a=actions, r=return value
        #
               
        if x.type in (Cmd.RESET, Cmd.CLEAR) or y.type in (Cmd.RESET, Cmd.CLEAR):
            print "Unsupported case!"
            assert False # not supported!!
            return None # not supported!!
          
        x_retvals = [xy_x.retval, yx_x.retval]
        y_retvals = [xy_y.retval, yx_y.retval]
        
        if x.type == Cmd.TRACE:
            # x is TRACE
            trace = x
            Tpka = trace.flowdesc
            Tp = trace.flowdesc.get_priority()
            Tk = trace.flowdesc.get_match()
            Ta = trace.flowdesc.get_actions()
        
            if y.type == Cmd.TRACE:
                return True #always commutes
        
            if y.type == Cmd.OF_ADD:
                # y is ADD
                add = y
                Apka = add.flowdesc
                Ap = add.flowdesc.get_priority()
                Ak = add.flowdesc.get_match()
                Aa = add.flowdesc.get_actions()
                
                def _trace_add(Tr,Ar):
                  Tr_read = Tr
                  Ar_added = Ar[0]
                  Ar_before_matches = Ar[1]
                  # is the TRACE key a subset of the ADD key?
                  Tk_is_subset_of_Ak = self.comparator.is_subset(Tk,Ak)
                  # which rule would TRACE use from the overridden/hidden rules
                  select_Tk_from_Ar = self.comparator.select(Tk,Ar_before_matches)
                  
                  
                  return (
                          Tr_read not in Ar_added and
                          Tk_is_subset_of_Ak and
                          Ap >= Tr.get_priority() and
                          Aa != Tr.get_actions()
                          ) or (
                          Tr_read in Ar_added and 
                          select_Tk_from_Ar.get_actions() != Tr_read.get_actions()
                          )
                  
                # To be a valid specification, the rule has to produce the same output for each case. In reality,
                # only one of the cases will be available for checking.
                case1 = _trace_add(x_retvals[0], y_retvals[0])
                case2 = _trace_add(x_retvals[1], y_retvals[1])
                assert case1 == case2
                return not case1
              
            if y.type == Cmd.OF_DEL:
                # y is DEL
                delete = y
                Dpka = delete.flowdesc
                Dp = delete.flowdesc.get_priority()
                Dk = delete.flowdesc.get_match()
                Da = delete.flowdesc.get_actions()
                
                def _trace_delete(Tr,Dr):
                  Tr_read = Tr
                  Dr_deleted = Dr[0]
                  Dr_aftermatches = Dr[1]
                  
                  select_Tk_Dr_aftermatches = self.comparator.select(Tk, Dr_aftermatches)                 
                  select_Tk_Dr_deleted = self.comparator.select(Tk, Dr_deleted)                 
                  
                  return (
                          Tr_read in Dr_deleted and
                          select_Tk_Dr_aftermatches.get_actions() != Tr.get_actions()
                          ) or (
                          Tr_read not in Dr_deleted and 
                          select_Tk_Dr_deleted.get_priority() >= Tr_read.get_priority() and
                          select_Tk_Dr_deleted.get_actions() != Tr_read.get_actions()
                          )
                  
                case1 = _trace_delete(x_retvals[0], y_retvals[0])
                case2 = _trace_delete(x_retvals[1], y_retvals[1])
                assert case1 == case2
                return not case1
              
            if y.type == Cmd.OF_MOD:
                # y is MOD
                modify = y
                Mpka = modify.flowdesc
                Mp = modify.flowdesc.get_priority()
                Mk = modify.flowdesc.get_match()
                Ma = modify.flowdesc.get_actions()
                
                def _trace_modify(Tr,Mr):
                  Tr_read = Tr
                  is_add = Mr[0]
                  if is_add:
                    # uninteresting case, same as an add
                    return None # not supported!! TODO: handle this better
                  Mr_before_to_after = Mr[1]
                  Mr_after_to_before = Mr[2]
                  
                  return (
                          Tr_read in Mr_before_to_after is not None and Tr_read in Mr_before_to_after.keys() and
                          Mr_before_to_after[Tr_read].get_actions() != Tr_read.get_actions()
                          ) or (
                           Tr_read in Mr_after_to_before is not None and Tr_read not in Mr_after_to_before.keys() and 
                          Mr_after_to_before[Tr_read].get_actions() != Tr_read.get_actions()
                          )
                  
                case1 = _trace_modify(x_retvals[0], y_retvals[0])
                case2 = _trace_modify(x_retvals[1], y_retvals[1])
                if case1 is None or case2 is None:
                  self.last_none_was_mod_as_add = True
                  return None
                assert case1 == case2
                return not case1      
              
        if x.type == Cmd.OF_ADD:
          # x is ADD
          add = x
          Apka = add.flowdesc
          Ap = add.flowdesc.get_priority()
          Ak = add.flowdesc.get_match()
          Aa = add.flowdesc.get_actions()
      
          if y.type == Cmd.OF_ADD:
            add2 = x
            A2pka = add2.flowdesc
            A2p = add2.flowdesc.get_priority()
            A2k = add2.flowdesc.get_match()
            A2a = add2.flowdesc.get_actions()
            
            
            def _add_add(A1r,A2r):
              is_overwrite = A1r[2] or A2r[2]
              return not is_overwrite and Ap == A2p and Ak == A2k and Aa != A2a
          
            case1 = _add_add(x_retvals[0], y_retvals[0])
            return not case1
            
          if y.type == Cmd.OF_DEL:
            delete = y
            Dpka = delete.flowdesc
            Dp = delete.flowdesc.get_priority()
            Dk = delete.flowdesc.get_match()
            Da = delete.flowdesc.get_actions()
            
            def _add_delete(Ar,Dr):
              Ar_added = Ar[0]
              
              Ar_before_matches = Ar[1]
              Dr_deleted = Dr[0]
              Dr_aftermatches = Dr[1]
              
              Ak_is_subset_of_Dk = self.comparator.is_subset(Ak,Dk)
              
              return (
                      Ar_added in Dr_deleted
                      ) or (
                      Ak_is_subset_of_Dk
                      # TODO JM: Do (out_port) is NOT handled
                      # TODO JM: is_strict is NOT handled
                      )
              
            case1 = _add_delete(x_retvals[0], y_retvals[0])
            case2 = _add_delete(x_retvals[1], y_retvals[1])
            assert case1 == case2
            return not case1
          
          if y.type == Cmd.OF_MOD:
            # y is MOD
            modify = y
            Mpka = modify.flowdesc
            Mp = modify.flowdesc.get_priority()
            Mk = modify.flowdesc.get_match()
            Ma = modify.flowdesc.get_actions()
            
            def _add_modify(Ar,Mr):
              Ar_added = Ar[0]
              Ar_before_matches = Ar[1]
              
              is_add = Mr[0]
              if is_add:
                # uninteresting case, same as an add
                return None # not supported!! TODO: handle this better
              Mr_before_to_after = Mr[1]
              Mr_after_to_before = Mr[2]
              
              return (
                       Mr_before_to_after is not None and Ar_added in Mr_before_to_after.keys() and
                      Mr_before_to_after[Ar_added].get_actions() != Ar_added.get_actions()
                      ) or (
                       Mr_after_to_before is not None and Ar_added not in Mr_after_to_before.keys() and 
                      Mr_after_to_before[Ar_added].get_actions() != Ar_added.get_actions()
                      )
              
            case1 = _add_modify(x_retvals[0], y_retvals[0])
            case2 = _add_modify(x_retvals[1], y_retvals[1])
            if case1 is None or case2 is None:
              self.last_none_was_mod_as_add = True
              return None
            assert case1 == case2
            return not case1   
              
        if x.type == Cmd.OF_DEL:
          if y.type == Cmd.OF_DEL:
            return True
          
          if y.type == Cmd.OF_MOD:
            # y is MOD
            modify = y
            Mpka = modify.flowdesc
            Mp = modify.flowdesc.get_priority()
            Mk = modify.flowdesc.get_match()
            Ma = modify.flowdesc.get_actions()
            
            def _del_modify(Dr,Mr):
              Dr_deleted = Dr[0]
              Dr_aftermatches = Dr[1]
              is_add = Mr[0]
              if is_add:
                # uninteresting case, same as an add
                return None # not supported!! TODO: handle this better
              Mr_before_to_after = Mr[1]
              Mr_after_to_before = Mr[2]
              
              # TODO JM: Do (out_port) is NOT handled
              # TODO JM: is_strict is NOT handled
              
              return True
              
            case1 = _del_modify(x_retvals[0], y_retvals[0])
            case2 = _del_modify(x_retvals[1], y_retvals[1])
            if case1 is None or case2 is None:
              self.last_none_was_mod_as_add = True
              return None
            assert case1 == case2
            return not case1
          
        if x.type == Cmd.OF_MOD:
          # x is MOD
          modify = x
          Mpka = modify.flowdesc
          Mp = modify.flowdesc.get_priority()
          Mk = modify.flowdesc.get_match()
          Ma = modify.flowdesc.get_actions()
          if y.type == Cmd.OF_MOD:
            # y is MOD
            modify2 = y
            M2pka = modify2.flowdesc
            M2p = modify2.flowdesc.get_priority()
            M2k = modify2.flowdesc.get_match()
            M2a = modify2.flowdesc.get_actions()
            
            def _modify_modify(Mr,Mr2):
              is_add = Mr[0]
              is_add2 = Mr2[0]
              if is_add or is_add2:
                # uninteresting case, same as an add
                return None # not supported!! TODO: handle this better
              Mr_before_to_after = Mr[1]
              Mr_after_to_before = Mr[2]
              Mr2_before_to_after = Mr2[1]
              Mr2_after_to_before = Mr2[2]
              
              if Mr_before_to_after is None:
                Mr_before_to_after = []
              if Mr_after_to_before is None:
                Mr_after_to_before = []
              if Mr2_before_to_after is None:
                Mr2_before_to_after = []
              if Mr2_after_to_before is None:
                Mr2_after_to_before = []
                
              before1 = set(Mr_before_to_after.keys()) 
              before2 = set(Mr2_before_to_after.keys())
              after1 = set(Mr_after_to_before.keys())
              after2 = set(Mr2_after_to_before.keys())
              
              if len(after1.intersection(before2)) > 0:
                return False
              if len(after2.intersection(before1)) > 0:
                return False
              return True
              
            case1 = _modify_modify(x_retvals[0], y_retvals[0])
            case2 = _modify_modify(x_retvals[1], y_retvals[1])
            if case1 is None or case2 is None:
              self.last_none_was_mod_as_add = True
              return None
            assert case1 == case2
            return not case1

        # NOTE:
        #       with the new rule the rest of the testcases are trivial, 
        #       as we would just do the same or similar comparison as is done in:
        #       CommutativityTestCase.evaluate. There is nothing to gain 
        #       as we cannot predict anything without the information in
        #       the return values.
        #       The remaining combinations are very similar to add_modify.
        #
            
                
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
            t.remove_check_overlap()
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
        """Return all flows that are a subset of s (are more strict than s)
        """
        subset_flows = set()
        for t in flow_set:
            if self.is_subset(t, s): #s is more general
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
        """Return all flows that are a superset of s (s is a subset of) (are more general than s)
        """
        superset_flows = set()
        for t in flow_set:
            if self.is_subset(s, t):
                superset_flows.add(t)
        return superset_flows

    def is_subset(self,s,t):
        """Do all packets matching s also match t (t is more general)?
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
        # special maps for OF_MOD
        self.before_to_after = None
        self.after_to_before = None
        
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
                superset_flows = set() # superset_flows will never be used
                break
        for x in self.added_flows:
          x.remove_statistics()
        for x in superset_flows:
          x.remove_statistics()
        is_overwrite = False
        if self.overwritten_flows is not None and len(self.overwritten_flows) > 0:
          is_overwrite = True
        return (self.added_flows, superset_flows, is_overwrite)

    def _retval_of_del(self,comparator):
        # Return all rules that were removed by the deletion.
        # Also return the superset to be more precise
        s = FlowDescription(str(self.cmd.flowdesc))
        s.remove_statistics()
        s.remove_priority()
        s.remove_actions()
        superset_flows = comparator.superset_set(s, self.before_set)
        superset_flows = superset_flows.difference(self.removed_flows)
        for t in superset_flows:
            t_prio = t.get_priority()
            for v in self.removed_flows:
              v_prio = v.get_priority()
              if t_prio > v_prio:
                superset_flows = set() # superset_flows will never be used
                break
        for x in self.removed_flows:
          x.remove_statistics()
        for x in superset_flows:
          x.remove_statistics()
        return (self.removed_flows, superset_flows)
    def _retval_of_mod(self,comparator):
        # MODIFY works as ADD if there is nothing to modify
        is_add = False
        if len(self.added_flows) > 0:
          is_add = True 
        if is_add:
          add_retvals = self._retval_of_add(comparator) 
          return (is_add, add_retvals)
        else:
          if self.before_to_after is not None:
            for x in self.before_to_after.keys():
              x.remove_statistics()
          if self.after_to_before is not None:
            for x in self.after_to_before.keys():
              x.remove_statistics()
          return (is_add, self.before_to_after, self.after_to_before)
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

            result.removed_flows = result.before_set.difference(result.after_set) # in before, but not after
            result.added_flows = result.after_set.difference(result.before_set) # in after, but not before
            result.affected_flows = result.before_set.symmetric_difference(result.after_set)
            
            if cmd == Cmd.OF_MOD:
              result.before_to_after = []
              result.after_to_before = []
              
              for b in result.removed_flows:
                # find corresponding flow in added table
                x = b.get_get_match_priority()
                for a in result.added_flows:
                  y = a.get_match_priority()
                  if x == y:
                    result.before_to_after[b] = a
                    result.after_to_before[a] = b
            
            # OF_ADD is a special case, as it may overwrite itself but we have no way to detect this with OVS (we could look at the 'duration' field but that is not guaranteed to work)
            if cmd == Cmd.OF_ADD and len(result.affected_flows) == 0:
                result.overwritten_flows.add(cmd.flowdesc)
                result.added_flows.add(cmd.flowdesc)
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
            f = FlowDescription(str(cmd.flowdesc))
            f.remove_priority()
            lines = run_cmdline_string('ovs-ofctl mod-flows '+self.switchdesc.name+' "'+str(f)+'"',noerr=True)
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
    
    def remove_check_overlap(self):
        self.fields.pop('check_overlap',None)
    
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
      
    def get_match_priority(self):
        """Get a copy of this FlowDescription with stats, actions removed.
        :rtype: FlowDescription
        """
        result = self.copy()
        result.remove_statistics()
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
    