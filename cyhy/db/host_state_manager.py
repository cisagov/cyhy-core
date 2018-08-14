__all__ = ['DefaultHostStateManager']

from cyhy.core.common import *
import logging

class DefaultHostStateManager(object):
    '''Handles the transition of hosts between states (stage,status)'''
        
    def __init__(self):
        self.__logger = logging.getLogger(__name__)
    
    def transition(self, host_doc, up=None, has_open_ports=None, was_failure=False):
        '''applies a transition of state to a HostDoc.
           returns: True if there was a change, False otherwise.
        '''
        new_stage, new_status, was_changed, finished_stage = self.new_state(host_doc, up, has_open_ports, was_failure)
        
        if was_changed:
            host_doc['stage'] = new_stage
            host_doc['status'] = new_status
        
        return was_changed, finished_stage
    
    def new_state(self, host_doc, up=None, has_open_ports=None, was_failure=False):
        '''calculates the new state for a host.
           returns: stage, status, was_changed, finished_stage
        '''
        stage = host_doc['stage']
        status = host_doc['status']
        
        # NoOps: Done is Done.
        if status == STATUS.DONE:
            return (stage, status, False, False)
        
        # Failures change to WAITING status, unless they're already WAITING, or DONE (see above).
        if was_failure:
            was_changed = status != STATUS.WAITING
            return (stage, STATUS.WAITING, was_changed, False)
        
        # All hosts move from READY to RUNNING
        # It is possible to request WAITING hosts from the command line tools
        # so we need to handle that case here.
        if status in [STATUS.WAITING, STATUS.READY]:
            return (stage, STATUS.RUNNING, True, False)
        
        # interesting cases
        if status == STATUS.RUNNING:
            if stage == STAGE.NETSCAN1:
                if up:
                    return (STAGE.PORTSCAN, STATUS.WAITING, True, True)
                else:
                    return (STAGE.NETSCAN2, STATUS.WAITING, True, True)
                    
            elif stage == STAGE.NETSCAN2:
                if up:
                    return (STAGE.PORTSCAN, STATUS.WAITING, True, True)
                else:
                    return (STAGE.NETSCAN2, STATUS.DONE, True, True)
            
            elif stage == STAGE.PORTSCAN:
                if has_open_ports:
                    return (STAGE.VULNSCAN, STATUS.WAITING, True, True)
                else:
                    return (STAGE.PORTSCAN, STATUS.DONE, True, True)
            
            elif stage in [STAGE.VULNSCAN, STAGE.BASESCAN]:
                return (stage, STATUS.DONE, True, True)
                
        self.__logger.warning('Host arrived in a state we were not prepared to handle [%s, %s]' % (stage,status))
        return (stage, status, False, False)
                
                