'''
Queries used by the core components
'''

import database

def addresses_scanned_pl(owners):
    return  [
            {'$match': {'owner':{'$in':owners}, 'latest_scan.DONE':{'$ne':None}}},
            {'$group': {'_id':{},
                        'addresses_scanned':{'$sum':1},
                       }
            },
            ], database.HOST_COLLECTION

def host_count_pl(owners):
    return  [
            {'$match': {'owner':{'$in':owners}, 'state.up':True}},
            {'$group': {'_id':{},
                        'host_count':{'$sum':1},
                       }
            },
            ], database.HOST_COLLECTION

def vulnerable_host_count_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid}},
            {'$group': {'_id': {'ip':'$ip'},
                        }
            },
            {'$group': {'_id':{},
                        'vulnerable_host_count':{'$sum':1},
                       }
            },
            ], database.TICKET_COLLECTION

def unique_operating_system_count_pl(snapshot_oid):
    '''nmap host records contain a "name" field'''
    return  [
            {'$match': {'snapshots':snapshot_oid, 'name':{'$exists':True}}},
            {'$group':{'_id':   {'ip':'$ip',
                                 'operating_system':'$name',
                                 }
                      }
            },
            {'$group':{'_id':   {'operating_system':'$_id.operating_system'}
                      }
            },
            {'$group':{'_id': {},
                      'unique_operating_systems':{'$sum':1}
                      }
            },
            ], database.HOST_SCAN_COLLECTION

def severity_count_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid, 'false_positive':False}},
            {'$group': {'_id': {},
                        'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                        'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                        'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                        'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                        'total':{'$sum':1},
                        }
            }
            ], database.TICKET_COLLECTION

def unique_severity_count_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid, 'false_positive':False}},
            {'$group': {'_id': {'source_id':'$source_id',
                                'severity':'$details.severity'}
                       }
            },
            {'$group': {'_id': {'severity':'$severity'},
                        'low':{'$sum':{'$cond':[{'$eq':['$_id.severity',1]}, 1, 0]}},
                        'medium':{'$sum':{'$cond':[{'$eq':['$_id.severity',2]}, 1, 0]}},
                        'high':{'$sum':{'$cond':[{'$eq':['$_id.severity',3]}, 1, 0]}},
                        'critical':{'$sum':{'$cond':[{'$eq':['$_id.severity',4]}, 1, 0]}},
                        'total':{'$sum':1},
                        }
            }
            ], database.TICKET_COLLECTION

def port_count_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid}},
            {'$group': {'_id': {'port':'$port',
                                'ip':'$ip'},
                        }
            },
            {'$group': {'_id':{},
                        'port_count':{'$sum':1},
                       }
            },
            ], database.PORT_SCAN_COLLECTION

def unique_port_count_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid}},
            {'$group': {'_id': {'port':'$port'},
                        }
            },
            {'$group': {'_id':{},
                        'unique_port_count':{'$sum':1},
                       }
            },
            ], database.PORT_SCAN_COLLECTION

def silent_port_count_pl(owners):
    return  [
            {'$match': {'latest':True, 'owner':{'$in':owners}, 'state':'silent'}},
            {'$group': {'_id':{},
                        'silent_port_count':{'$sum':1},
                       }
            },
            ], database.PORT_SCAN_COLLECTION

def service_counts_simple_pl(snapshot_oid):
    # TODO report on unknown services.
    # TODO some nmap reports do not have a service field
    return  [
            {'$match': {'snapshots':snapshot_oid, 'service.name':{'$exists':True, '$ne':'unknown'}}},
            {'$group':{'_id':   {'ip':'$ip',
                                 'port':'$port',
                                 'service_name':'$service.name',
                                 }
                      }
            },
            {'$group':{'_id':   {'service_name':'$_id.service_name',
                                },
                      'count':{'$sum':1}
                      }
            },
            {'$sort': {'count':-1}}
            ], database.PORT_SCAN_COLLECTION

def cvss_sum_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid}},
            # host cvss is the max of any cvss for that host
            {'$group': {'_id':{'ip':'$ip',},
                        'cvss_max':{'$max':'$details.cvss_base_score'},
                       }
            },
            # calculate sum of all host maximums
            {'$group': {'_id':{},
                        'cvss_sum':{'$sum':'$cvss_max'},
                       }
            },
            ], database.TICKET_COLLECTION

def time_span(snapshot_oid):
    '''This query doesn't have an associated collection defined
    as it is executed against multiple collections.'''
    return  [
            {'$match': {'snapshots':snapshot_oid}}, # contains oid
            {'$group': {'_id':{},
                        'start_time':{'$min':'$time'},
                        'end_time':{'$max':'$time'},
                       }
            },
            ] # vuln, host, port

def host_time_span(owners):
    return  [
            {'$match': {'owner':{'$in':owners}}},
            {'$group': {'_id':{},
                        'start_time':{'$min':'$last_change'},
                        'end_time':{'$max':'$last_change'},
                       }
            },
            ], database.HOST_COLLECTION

def close_tickets_pl(ip_ints, ports, source_ids, not_ticket_ids, source):
    return [
           {'$match': {'open':True, 'ip_int':{'$in':ip_ints}, 'source':source}},
           {'$match': {'_id':{'$nin':not_ticket_ids}}},
           {'$match': {'source_id':{'$in':source_ids}}},
           {'$match': {'$or':[{'port':{'$in':ports}},{'protocol':'udp'}]}},
           ], database.TICKET_COLLECTION

def clear_latest_vulns_pl(ip_ints, ports, source_ids, source):
    return [
           {'$match': {'latest':True, 'ip_int':{'$in':ip_ints}, 'source':source}},
           {'$match': {'port':{'$in':ports}}},
           {'$match': {'plugin_id':{'$in':source_ids}}},
           ], database.VULN_SCAN_COLLECTION

def max_severity_for_host(ip_int):
    return  [
            {'$match': {'ip_int':ip_int, 'open':True}},
            # host cvss is the max of any cvss for that host
            {'$group': {'_id':{},
                        'severity_max':{'$max':'$details.severity'},
                       }
            },
            ], database.TICKET_COLLECTION

def false_positives_pl(snapshot_oid):
    return  [
            {'$match': {'snapshots':snapshot_oid, 'false_positive':True}},
            {'$group': {'_id': {},
                        'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                        'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                        'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                        'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                        'total':{'$sum':1},
                        }
            }
            ], database.TICKET_COLLECTION

def open_ticket_age_in_snapshot_pl(open_as_of_date, snapshot_oid):
    return [
           {'$match': {'snapshots':snapshot_oid, 'false_positive':False}},
           {'$project': {'_id':0,
                         'severity':'$details.severity',
                         'open_msec':{'$subtract': [open_as_of_date, '$time_opened']}}
                        },
           {'$sort': {'severity':1, 'open_msec':1}},
           ], database.TICKET_COLLECTION

def closed_ticket_age_for_orgs_pl(closed_since_date, org_list):
    return [
           {'$match': {'open':False, 'time_closed':{'$gte':closed_since_date}, 'owner':{'$in':org_list}}},
           {'$project': {'_id':0,
                         'severity':'$details.severity',
                         'msec_to_close':{'$subtract': ['$time_closed', '$time_opened']}}
                        },
           {'$sort': {'severity':1, 'msec_to_close':1}},
           ], database.TICKET_COLLECTION

#######################################
# World Pipelines
#######################################

def world_pl(snapshots_to_exclude):
    return  [
            {'$match': {'latest':True, '_id':{'$nin':snapshots_to_exclude}}},
            {'$group': {'_id':{},
                        'host_count':{'$sum':'$host_count'},
                        'vulnerable_host_count':{'$sum':'$vulnerable_host_count'},
                        'vulnerabilities_low':{'$sum':'$vulnerabilities.low'},
                        'vulnerabilities_medium':{'$sum':'$vulnerabilities.medium'},
                        'vulnerabilities_high':{'$sum':'$vulnerabilities.high'},
                        'vulnerabilities_critical':{'$sum':'$vulnerabilities.critical'},
                        'vulnerabilities_total':{'$sum':'$vulnerabilities.total'},
                        'unique_vulnerabilities_low':{'$sum':'$unique_vulnerabilities.low'},
                        'unique_vulnerabilities_medium':{'$sum':'$unique_vulnerabilities.medium'},
                        'unique_vulnerabilities_high':{'$sum':'$unique_vulnerabilities.high'},
                        'unique_vulnerabilities_critical':{'$sum':'$unique_vulnerabilities.critical'},
                        'unique_vulnerabilities_total':{'$sum':'$unique_vulnerabilities.total'},
                       }
            },
            {'$project': {'host_count':True,
                          'vulnerable_host_count':True,
                          'unique_vulnerabilities.low':'$unique_vulnerabilities_low',
                          'unique_vulnerabilities.medium':'$unique_vulnerabilities_medium',
                          'unique_vulnerabilities.high':'$unique_vulnerabilities_high',
                          'unique_vulnerabilities.critical':'$unique_vulnerabilities_critical',
                          'unique_vulnerabilities.total':'$unique_vulnerabilities_total',
                          'vulnerabilities.low':'$vulnerabilities_low',
                          'vulnerabilities.medium':'$vulnerabilities_medium',
                          'vulnerabilities.high':'$vulnerabilities_high',
                          'vulnerabilities.critical':'$vulnerabilities_critical',
                          'vulnerabilities.total':'$vulnerabilities_total',
                         }
            },
            ], database.SNAPSHOT_COLLECTION
