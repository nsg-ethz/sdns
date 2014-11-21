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

import sympy
import collections

def a_greater10(t):
    return t.a > 10

def b_greater10(t):
    return t.b > 10

def hidden(t):
    """
    The "true" formula that we are trying to infer.
    :param a:
    :param b:
    :return:

    """
    a = t.a
    b = t.b
    if((a > 10 and b <= 10) or (a <= 10 and b > 10)):
        return True
    else:
        return False

def run_main():

    Flow = collections.namedtuple('Flow', ['a', 'b'])

    # create the testcases by some algorithm
    a_values = [0,11]
    b_values = [0,11]
    testcases = []

    for a, b in itertools.product(a_values,b_values):
        t = Flow(a,b)
        testcases.append(t)

    # create the truthtable

    positives = set()
    negatives = set()
    unknowns = set()

    for i in itertools.product([True,False],repeat=2):
        unknowns.add(i)


    # verify the testcases to generate the truth table
    atomic_formula_functions = [a_greater10,b_greater10]
    atomic_formula_strings = ['a_greater10','b_greater10']
    assert len(atomic_formula_functions) == len(atomic_formula_strings)

    for t in testcases:
        results = [None] * 2
        results[0] = atomic_formula_functions[0](t)
        results[1] = atomic_formula_functions[1](t)

        result_tup = tuple(results)

        if result_tup in unknowns:
            if hidden(t):
                positives.add(result_tup)
            else:
                negatives.add(result_tup)
            unknowns.remove(result_tup)
        else:
            print "Already processed such a testcase!"

    if len(unknowns) != 0:
        print "Not all possibilities covered by a testcase!"

    # transform truth table into a formula
    minterms = list(positives)
    dontcares = []

    result = sympy.boolalg.SOPform(atomic_formula_strings,minterms,dontcares)

    print(sympy.printing.latex(result))
    sympy.printing.pprint(result)






if __name__ == "__main__":
    run_main();