#!/usr/bin/env py.test -v 

import os
import sys

me = os.path.realpath(__file__)
myDir = os.path.dirname(me)
sys.path.append(os.path.join(myDir, '..'))

import pytest

import cyhy.util as util

IO_PAIRS = (([1,3,5,7,9], '1,3,5,7,9'),
             ([1],'1'),
             ([1,2,3,4,5], '1-5'),
             ([1,2,3,4,5,7,8,9,10],'1-5,7-10'),
             ([1,2,3,4,5,7,8,9,10,12],'1-5,7-10,12'),
             ([1,2,3,4,5,7,9,10,12],'1-5,7,9-10,12'),
             ([],''),
           )

@pytest.mark.parametrize(('int_list','range_string'), IO_PAIRS)
def test_list_to_range_string(int_list, range_string):
    actual_output = util.list_to_range_string(int_list)
    assert actual_output == range_string

@pytest.mark.parametrize(('int_list','range_string'), IO_PAIRS)    
def test_range_string_to_list(int_list, range_string):
    actual_output = util.range_string_to_list(range_string)
    assert actual_output == int_list

