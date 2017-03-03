# -*- coding: utf-8 -*-
# NOTE: this file is added by cannedfish

import sys
import json
import requests
import base64
import socket, fcntl, struct

from oslo_config import cfg
from oslo_log import log as logging

opts = [
    cfg.StrOpt('etcd_host',
            default='127.0.0.1',
            help='ETCD host on which to listen for incoming requests'),
    cfg.IntOpt('etcd_port',
            default=2379,
            min=1,
            max=65535,
            help='ETCD port on which to listen for incoming requests'),
    cfg.StrOpt('ifname',
            default='lo',
            help='The ifname of this node')
]

CONF = cfg.CONF
CONF.register_opts(opts, 'DEFAULT')
LOG = logging.getLogger(__name__)

LOG.debug("**********Params: %s, %d, %s" \
        % (CONF.DEFAULT.etcd_host, CONF.DEFAULT.etcd_port, CONF.DEFAULT.ifname))

ADDR_KEY = base64.b64encode('PUBLIC_LOGSERVERADDR')
LOG_ADDR = ''

def _get_client():
    try:
        ret = requests.post('http://%s:%d/v3alpha/kv/range' % \
                (CONF.DEFAULT.etcd_host, CONF.DEFAULT.etcd_port), \
                data=json.dumps({'key':ADDR_KEY}), timeout=2)
        global LOG_ADDR
        LOG_ADDR = base64.b64decode(ret.json()['kvs'][0]['value'])
        URL = 'http://%s/login' % LOG_ADDR

        # Initcloud API URL
        c = requests.session()

        # Retrieve the CSRF token first
        # Sets cookie
        c.get(URL, verify = False, timeout=2) 
        csrftoken = c.cookies['csrftoken']
        LOG.debug("******** csrftoken **********: %s" % csrftoken)

        # Authenticate
        # User created by initcloud(openstack user)
        login_data = dict(username='more', 
                password='ydd1121NN', 
                csrfmiddlewaretoken=csrftoken, 
                next='/')
        login_return = c.post(URL, data=login_data, headers=dict(Referer=URL))
        LOG.debug("*********** auth status *********: %s" % login_return.status_code)

        return c
    except Exception, e:
        LOG.error('Get auth client of initcloud failed: %s' % e)
        return None

# TODO: how to handle disconnect?
client = _get_client()

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
def _get_ip_address():
    """
    return the IP address of this node
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
                 s.fileno(),
                 0x8915,
                 struct.pack('256s', CONF.DEFAULT.ifname[:15]))[20:24])

# request ulr with get method
URL_ = "http://%s/api/operation/collector/" % LOG_ADDR
SELF_IP_ADDRESS = _get_ip_address()

def send_msg(user, resource, action, result, op_type, msg):
    """
    user: operator, default is 'auto'
    resource: the name of safe module
    action: which action did you perform
    result: the result of action, default is 1
    op_type: 0->logging, 1->alarm
    msg: message string
    """
    LOG.debug("*********** target: %s" % URL_)
    payload = {
        "user": user, 
        "resource": resource, 
        "resource_name": SELF_IP_ADDRESS, 
        "action": action, 
        "result": result, 
        "operation_type": op_type, 
        "message": msg
    }
    LOG.debug("*********** log payload: %s" % payload)

    try:
        operation_return = client.get(URL_, params=payload, timeout=2)

        LOG.debug("*********** return status is " + str(operation_return.status_code))
        LOG.debug("*********** return type   is " + str(operation_return.headers['content-type']))
        LOG.debug("*********** content       is \n" + str(operation_return.content))
    except Exception, e:
        LOG.error('GET %s: %s' % (URL_, e))

