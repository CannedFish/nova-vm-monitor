# -*- coding: utf-8 -*-

import sys
import json
import requests
import base64

from oslo_config import cfg
from oslo_log import log as logging

opts = [
    cfg.StrOpt('etcd_host',
            default='127.0.0.1',
            help='ETCD host on which to listen for incoming requests'),
    cfg.IntOpt('etcd_port',
            default='2379',
            min=1,
            max=65535,
            help='ETCD port on which to listen for incoming requests'),
]

CONF = cfg.CONF
CONF.register_cli_opts(opts)
LOG = logging.getLogger(__name__)

ADDR_KEY = base64.b64encode('PUBLIC_LOGSERVERADDR')
ret = requests.post('http://%s:%d/v3alpha/kv/range' % \
        (CONF.etcd_host, CONF.etcd_port), \
        data=json.dumps({'key':ADDR_KEY}))
LOG_ADDR = base64.b64decode(ret.json()['kvs'][0]['value'])

# Initcloud API URL
URL = 'http://%s/login' % LOG_ADDR

client = requests.session()

# Retrieve the CSRF token first
# Sets cookie
client.get(URL, verify = False) 
csrftoken = client.cookies['csrftoken']
print "******** csrftoken **********"
print csrftoken

# Authenticate
# User created by initcloud(openstack user)
login_data = dict(username='more', password='ydd1121NN', csrfmiddlewaretoken=csrftoken, next='/')
login_return = client.post(URL, data=login_data, headers=dict(Referer=URL))
print "*********** auth status *********"
print login_return.status_code


# Current Operation  Resource, added if necessary
"""
RESOURCE_CHOICES = (
    ("Instance", _("Instance")),
    ("Volume", _("Volume")),
    ("Network", _("Network")),
    ("Subnet", _("Subnet")),
    ("Router", _("Router")),
    ("Floating", _("Volume")),
    ("Firewall", _("Firewall")),
    ("FirewallRules", _("FirewallRules")),
    ("Contract", _("Contract")),
    ("BackupItem", _("BackupItem")),
)


RESOURCE_ACTION_CHOICES = (
    ("reboot", _("reboot")),
    ("power_on", _("power_on")),
    ("power_off", _("power_off")),
    ("vnc_console", _("vnc_console")),
    ("bind_floating", _("bind_floating")),
    ("unbind_floating", _("unbind_floating")),
    ("change_firewall", _("change_firewall")),
    ("attach_volume", _("attach_volume")),
    ("detach_volume", _("detach_volume")),
    ("terminate", _("terminate")),
    ("launch", _("launch")),
    ("create", _("create")),
    ("update", _("update")),
    ("delete", _("delete")),
    ("attach_router", _("attach router")),
    ("detach_router", _("detach router")),
)

Result = (
    ("1": _("success")),
    ("-1": _("failed")),
    ("0": _("error")),
)

Operation_Types(
    ("0": _("logging")),
    ("1": _("alarm")),
)

"""
# request ulr with get method
URL_ = "http://%s/api/operation/collector/" % LOG_ADDR

def send_msg(user, resource, resource_name, action, result, op_type, msg):
    """
    user: operator, default is 'auto'
    resource: the name of safe module
    resource_name: IP of this address
    action: which action did you perform
    result: the result of action, default is 1
    op_type: 0->logging, 1->alarm
    msg: message string
    """
    payload = {
        "user": user, 
        "resource": resource, 
        "resource_name": resource_name, 
        "action": action, 
        "result": result, 
        "operation_type": op_type, 
        "message": msg
    }

    try:
        operation_return = client.get(URL_, params=payload, timeout=2)

        LOG.debug("*********** return status is " + str(operation_return.status_code))
        LOG.debug("*********** return type   is " + str(operation_return.headers['content-type']))
        LOG.debug("*********** content       is \n" + str(operation_return.content))
    except Exception, e:
        LOG.error('GET %s: %s' % (URL_, e))

