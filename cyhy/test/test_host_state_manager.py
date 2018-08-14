#!/usr/bin/env py.test -v

import itertools
import pytest
from cyhy.db import DefaultHostStateManager, database
from cyhy.core.common import *
from common_fixtures import database, ch_db


@pytest.fixture
def state_manager():
    return DefaultHostStateManager()

@pytest.fixture
def h(database):
    h = database.HostDoc()
    return h

#@pytest.mark.parametrize(('sources'), [SOURCE_NESSUSS_1, SOURCE_NESSUSS_2, SOURCE_NESSUSS_3, SOURCE_NESSUSS_4], scope='class')
class TestStateManager:
    def test_get_instance(self, state_manager):
        assert state_manager != None
        
    @pytest.mark.parametrize(('status'), [STATUS.DONE])
    @pytest.mark.parametrize(('stage'), STAGE)
    def test_noops(self, h, state_manager, stage, status):
        h['status'] = status
        h['stage'] = stage
        was_changed = state_manager.transition(h)
        assert h['stage'] == stage, 'stage SHOULD NOT change when status is %s' % status
        assert was_changed == False, '"was_changed" should be False'
    
    @pytest.mark.parametrize(('status'), [STATUS.WAITING, STATUS.READY, STATUS.RUNNING])
    @pytest.mark.parametrize(('stage'), STAGE)
    def test_ops(self, h, state_manager, stage, status):
        h['status'] = status
        h['stage'] = stage
        was_changed = state_manager.transition(h)
        assert was_changed == True, '"was_changed" should be True'

    @pytest.mark.parametrize(('status'), [STATUS.READY, STATUS.RUNNING])
    @pytest.mark.parametrize(('stage'), STAGE)
    def test_was_failure(self, h, state_manager, stage, status):
        h['status'] = status
        h['stage'] = stage
        was_changed = state_manager.transition(h, was_failure=True)
        assert was_changed == True, '"was_changed" should be True'
        assert h['status'] == STATUS.WAITING, 'status should have transitioned from to WAITING but did not.'
        assert h['stage'] == stage, 'the stage should not have changed, but did'

    @pytest.mark.parametrize(('status'), [STATUS.WAITING, STATUS.DONE])
    @pytest.mark.parametrize(('stage'), STAGE)
    def test_was_failure_no_change(self, h, state_manager, stage, status):
        h['status'] = status
        h['stage'] = stage
        was_changed = state_manager.transition(h, was_failure=True)
        assert was_changed == False, '"was_changed" should be False'

    @pytest.mark.parametrize(('status'), [STATUS.WAITING, STATUS.READY])
    @pytest.mark.parametrize(('stage'), STAGE)
    def test_ready_waiting_to_running(self, h, state_manager, stage, status):
        h['stage'] = stage
        h['status'] = status
        was_changed = state_manager.transition(h)
        assert was_changed == True, '"was_changed" should be True'
        assert h['status'] == STATUS.RUNNING, 'status should have transitioned from READY to RUNNING but did not.'
        
    @pytest.mark.parametrize(('i_stage,up,f_stage,f_status'), 
                             [(STAGE.NETSCAN1, True, STAGE.PORTSCAN, STATUS.WAITING), 
                              (STAGE.NETSCAN1, False, STAGE.NETSCAN2, STATUS.WAITING),
                              (STAGE.NETSCAN2, True, STAGE.PORTSCAN, STATUS.WAITING),
                              (STAGE.NETSCAN2, False, STAGE.NETSCAN2, STATUS.DONE),
                              (STAGE.VULNSCAN, None, STAGE.VULNSCAN, STATUS.DONE),
                              (STAGE.BASESCAN, None, STAGE.BASESCAN, STATUS.DONE)])    
    def test_running_up_down(self, h, state_manager, i_stage, up, f_stage, f_status):
        h['stage'] = i_stage
        h['status'] = STATUS.RUNNING
        was_changed = state_manager.transition(h, up=up)
        assert was_changed == True, '"was_changed" should be True'
        assert h['stage'] == f_stage, 'stage should be %s' % f_stage
        assert h['status'] == f_status, 'status should be %s.' % f_status
              
    @pytest.mark.parametrize(('i_stage,has_open_ports,f_stage,f_status'), 
                             [(STAGE.PORTSCAN, True, STAGE.VULNSCAN, STATUS.WAITING), 
                              (STAGE.PORTSCAN, False, STAGE.PORTSCAN, STATUS.DONE)])    
    def test_running_open_ports(self, h, state_manager, i_stage, has_open_ports, f_stage, f_status):
        h['stage'] = i_stage
        h['status'] = STATUS.RUNNING
        was_changed = state_manager.transition(h, has_open_ports=has_open_ports)
        assert was_changed == True, '"was_changed" should be True'
        assert h['stage'] == f_stage, 'stage should be %s' % f_stage
        assert h['status'] == f_status, 'status should be %s.' % f_status
    
    #import IPython; IPython.embed() #<<< BREAKPOINT >>>
        