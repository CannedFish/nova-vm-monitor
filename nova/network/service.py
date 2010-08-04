# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Network Nodes are responsible for allocating ips and setting up network
"""

import logging

from twisted.internet import defer

from nova import datastore
from nova import flags
from nova import service
from nova import utils
from nova.auth import manager
from nova.network import exception
from nova.network import model

FLAGS = flags.FLAGS

flags.DEFINE_string('network_type',
                    'flat',
                    'Service Class for Networking')
flags.DEFINE_string('flat_network_bridge', 'br100',
                    'Bridge for simple network instances')
flags.DEFINE_list('flat_network_ips',
                  ['192.168.0.2','192.168.0.3','192.168.0.4'],
                  'Available ips for simple network')
flags.DEFINE_string('flat_network_network', '192.168.0.0',
                       'Network for simple network')
flags.DEFINE_string('flat_network_netmask', '255.255.255.0',
                       'Netmask for simple network')
flags.DEFINE_string('flat_network_gateway', '192.168.0.1',
                       'Broadcast for simple network')
flags.DEFINE_string('flat_network_broadcast', '192.168.0.255',
                       'Broadcast for simple network')
flags.DEFINE_string('flat_network_dns', '8.8.4.4',
                       'Dns for simple network')

def get_host_for_project(project_id):
    redis = datastore.Redis.instance()
    return redis.get(_host_key(project_id))

def _host_key(project_id):
    return "network_host:%s" % project_id


class BaseNetworkService(service.Service):
    """Implements common network service functionality

    This class must be subclassed.
    """
    def __init__(self, *args, **kwargs):
        self.network = model.PublicNetworkController()

    def get_network_host(self, user_id, project_id, *args, **kwargs):
        """Safely becomes the host of the projects network"""
        redis = datastore.Redis.instance()
        key = _host_key(project_id)
        if redis.setnx(key, FLAGS.node_name):
            return defer.succeed(FLAGS.node_name)
        else:
            return defer.succeed(redis.get(key))

    def allocate_fixed_ip(self, user_id, project_id,
                          security_group='default',
                          *args, **kwargs):
        """Subclass implements getting fixed ip from the pool"""
        raise NotImplementedError()

    def deallocate_fixed_ip(self, fixed_ip, *args, **kwargs):
        """Subclass implements return of ip to the pool"""
        raise NotImplementedError()

    def allocate_elastic_ip(self, user_id, project_id):
        """Gets a elastic ip from the pool"""
        # NOTE(vish): Replicating earlier decision to use 'public' as
        #             mac address name, although this should probably
        #             be done inside of the PublicNetworkController
        return self.network.allocate_ip(user_id, project_id, 'public')

    def associate_elastic_ip(self, elastic_ip, fixed_ip, instance_id):
        """Associates an elastic ip to a fixed ip"""
        self.network.associate_address(elastic_ip, fixed_ip, instance_id)

    def disassociate_elastic_ip(self, elastic_ip):
        """Disassociates a elastic ip"""
        self.network.disassociate_address(elastic_ip)

    def deallocate_elastic_ip(self, elastic_ip):
        """Returns a elastic ip to the pool"""
        self.network.deallocate_ip(elastic_ip)


class FlatNetworkService(BaseNetworkService):
    """Basic network where no vlans are used"""

    def allocate_fixed_ip(self, user_id, project_id,
                          security_group='default',
                          *args, **kwargs):
        """Gets a fixed ip from the pool

        Flat network just grabs the next available ip from the pool
        """
        redis = datastore.Redis.instance()
        if not redis.exists('ips') and not len(redis.keys('instances:*')):
            for fixed_ip in FLAGS.flat_network_ips:
                redis.sadd('ips', fixed_ip)
        fixed_ip = redis.spop('ips')
        if not fixed_ip:
            raise exception.NoMoreAddresses()
        return defer.succeed({'network_type': 'injected',
                'mac_address': utils.generate_mac(),
                'private_dns_name': str(fixed_ip),
                'bridge_name': FLAGS.flat_network_bridge,
                'network_network': FLAGS.flat_network_network,
                'network_netmask': FLAGS.flat_network_netmask,
                'network_gateway': FLAGS.flat_network_gateway,
                'network_broadcast': FLAGS.flat_network_broadcast,
                'network_dns': FLAGS.flat_network_dns})

    def deallocate_fixed_ip(self, fixed_ip, *args, **kwargs):
        """Returns an ip to the pool"""
        datastore.Redis.instance().sadd('ips', fixed_ip)

class VlanNetworkService(BaseNetworkService):
    """Vlan network with dhcp"""

    def allocate_fixed_ip(self, user_id, project_id,
                          security_group='default',
                          vpn=False, *args, **kwargs):
        """Gets a fixed ip from the pool """
        mac = utils.generate_mac()
        net = model.get_project_network(project_id)
        if vpn:
            fixed_ip = net.allocate_vpn_ip(user_id, project_id, mac)
        else:
            fixed_ip = net.allocate_ip(user_id, project_id, mac)
        return defer.succeed({'network_type': 'dhcp',
                'bridge_name': net['bridge_name'],
                'mac_address': mac,
                'private_dns_name' : fixed_ip})

    def deallocate_fixed_ip(self, fixed_ip,
                            *args, **kwargs):
        """Returns an ip to the pool"""
        return model.get_network_by_address(fixed_ip).deallocate_ip(fixed_ip)

    def lease_ip(self, address):
        return model.get_network_by_address(address).lease_ip(address)

    def release_ip(self, address):
        return model.get_network_by_address(address).release_ip(address)

    def restart_nets(self):
        """ Ensure the network for each user is enabled"""
        for project in manager.AuthManager().get_projects():
            model.get_project_network(project.id).express()


