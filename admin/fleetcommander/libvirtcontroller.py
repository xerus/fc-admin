# -*- coding: utf-8 -*-
# vi:ts=4 sw=4 sts=4

# Copyright (C) 2015 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the licence, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.
#
# Authors: Alberto Ruiz <aruiz@redhat.com>
#          Oliver Gutiérrez <ogutierrez@redhat.com>

import os
import signal
import time
import uuid
import subprocess
import socket
import xml.etree.ElementTree as ET

import libvirt

import sshcontroller

class LibVirtControllerException(Exception):
    pass


class LibVirtController(object):
    """
    Libvirt based session controller
    """

    RSA_KEY_SIZE = 2048
    DEFAULT_LIBVIRTD_SOCKET = '$XDG_RUNTIME_DIR/libvirt/libvirt-sock'
    LIBVIRT_URL_TEMPLATE = 'qemu+ssh://%s@%s/%s'
    MAX_SESSION_START_TRIES = 3
    SESSION_START_TRIES_DELAY = .1
    MAX_DOMAIN_UNDEFINE_TRIES = 3
    DOMAIN_UNDEFINE_TRIES_DELAY = .1

    def __init__(self, data_path, username, hostname, mode, admin_hostname, admin_port):
        """
        Class initialization
        """
        if mode not in ['system', 'session']:
            raise LibVirtControllerException('Invalid libvirt mode selected. Must be "system" or "session"')
        self.mode = mode

        # Connection data
        self.username = username
        self.hostname = hostname

        # SSH connection parameters
        if hostname:
            hostport = hostname.split(':')
            if len(hostport) == 1:
                hostport.append(22)
            self.ssh_host, self.ssh_port = hostport

        # Admin data
        self.admin_hostname = admin_hostname
        self.admin_port = admin_port

        # libvirt connection
        self.conn = None

        self.data_dir = os.path.abspath(data_path)
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.private_key_file = os.path.join(self.data_dir, 'id_rsa')
        self.public_key_file = os.path.join(self.data_dir, 'id_rsa.pub')
        self.known_hosts_file = os.path.join('/root/.ssh/', 'known_hosts')

        self.ssh = sshcontroller.SSHController()

        # generate key if neeeded
        if not os.path.exists(self.private_key_file):
            self.ssh.generate_ssh_keypair(self.private_key_file)

    def _prepare_remote_env(self):
        """
        Runs virsh remotely to execute the session daemon and get needed data for connection
        """
        # Check if host key is already in known_hosts
        # known = self.ssh.check_known_host(self.known_hosts_file, self.ssh_host)
        # if not known:
        #     self.ssh.add_to_known_hosts(
        #         self.known_hosts_file, self.ssh_host, self.ssh_port)

        if self.mode == 'session':
            command = 'virsh list > /dev/null && echo %s && [ -S %s ]' % (
                self.DEFAULT_LIBVIRTD_SOCKET, self.DEFAULT_LIBVIRTD_SOCKET)
        else:
            command = 'virsh list > /dev/null'

        error = None

        try:
            out = self.ssh.execute_remote_command(
                command,
                self.private_key_file,
                self.username, self.ssh_host, self.ssh_port,
                UserKnownHostsFile=self.known_hosts_file,
            )
            return out.strip()
        except Exception as e:
            raise LibVirtControllerException('Error connecting to host: %s' % e)

    def _connect(self):
        """
        Makes a connection to a host using libvirt qemu+ssh
        """
        if self.conn is None:
            self._libvirt_socket = self._prepare_remote_env()

            options = {
                #'known_hosts': self.known_hosts_file,  # Custom known_hosts file to not alter the default one
                'keyfile': self.private_key_file,  # Private key file generated by Fleet Commander
                # 'no_verify': '1',  # Add hosts automatically to  known hosts
                'no_tty': '1',  # Don't ask for passwords, confirmations etc.
                'sshauth': 'privkey',
            }

            if self.mode == 'session':
                options['socket'] = self._libvirt_socket
            url = self.LIBVIRT_URL_TEMPLATE % (self.username, self.hostname, self.mode)
            connection_uri = '%s?%s' % (
                url,
                '&'.join(['%s=%s' % (key, value) for key, value in sorted(options.items())])
            )
            try:
                self.conn = libvirt.open(connection_uri)
            except Exception as e:
                raise LibVirtControllerException('Error connecting to host: %s' % e)

    def _get_spice_parms(self, domain):
        """
        Obtain spice connection parameters for specified domain
        """
        # Get SPICE uri
        tries = 0
        while True:
            root = ET.fromstring(domain.XMLDesc())
            for elem in root.iter('graphics'):
                try:
                    if elem.attrib['type'] == 'spice':
                        port = elem.attrib['port']
                        listen = elem.attrib['listen']
                        return (listen, port)
                except:
                    pass

            if tries < self.MAX_SESSION_START_TRIES:
                time.sleep(self.SESSION_START_TRIES_DELAY)
                tries += 1
            else:
                raise LibVirtControllerException('Can not obtain SPICE URI for virtual session')

    def _generate_new_domain_xml(self, xmldata):
        """
        Generates new domain XML from given XML data
        """
        # Parse XML
        root = ET.fromstring(xmldata)
        # Add QEMU Schema
        root.set('xmlns:qemu', 'http://libvirt.org/schemas/domain/qemu/1.0')
        # Add QEMU command line option -snapshot
        cmdline = ET.SubElement(root, 'qemu:commandline')
        cmdarg = ET.SubElement(cmdline, 'qemu:arg')
        cmdarg.set('value', '-snapshot')
        # Change domain UUID
        newuuid = str(uuid.uuid4())
        root.find('uuid').text = newuuid
        # Change domain name
        root.find('name').text = 'fc-%s' % (newuuid[:8])
        # Change domain title
        try:
            title = root.find('title').text
            root.find('title').text = '%s - Fleet Commander temporary session' % (title)
        except:
            pass
        # Remove domain MAC addresses
        devs = root.find('devices')
        for elem in devs.findall('interface'):
            mac = elem.find('mac')
            if mac is not None:
                elem.remove(mac)
        # Remove all graphics adapters and create our own
        for elem in devs.findall('graphics'):
            devs.remove(elem)
        graphics = ET.SubElement(devs, 'graphics')
        graphics.set('type', 'spice')
        graphics.set('autoport', 'yes')
        channel = ET.SubElement(devs, 'channel')
        channel.set('type', 'pty')
        target = ET.SubElement(channel, 'target')
        target.set('type', 'virtio')
        target.set('name', 'fleet-commander_%s-%s' % (self.admin_hostname, self.admin_port))
        return ET.tostring(root)

    def _open_ssh_tunnel(self, host, spice_port):
        """
        Open SSH tunnel for spice port
        """
        # Get a free random local port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        addr = s.getsockname()
        local_port = addr[1]
        s.close()
        # Execute SSH and bring up tunnel
        try:
            pid = self.ssh.open_tunnel(
                local_port,
                host,
                spice_port,
                self.private_key_file,
                self.username, self.ssh_host, self.ssh_port,
                UserKnownHostsFile=self.known_hosts_file,
            )
            return (local_port, pid)
        except Exception as e:
            raise LibVirtControllerException('Error opening tunnel: %s' % e)

    def _undefine_domain(self, domain):
        """
        Undefines a domain waiting to be reported as defined to libVirt
        """
        try:
            persistent = domain.isPersistent()
        except:
            return

        if persistent:
            tries = 0
            while True:
                try:
                    domain.undefine()
                    break
                except:
                    pass
                if tries < self.MAX_DOMAIN_UNDEFINE_TRIES:
                    time.sleep(self.DOMAIN_UNDEFINE_TRIES_DELAY)
                    tries += 1
                else:
                    break

    def list_domains(self):
        """
        Returns a dict with uuid and domain name
        """
        self._connect()
        domains = self.conn.listAllDomains()

        def domain_name(dom):
            try:
                return dom.metadata(libvirt.VIR_DOMAIN_METADATA_TITLE, None)
            except Exception as e:
                print e
                return dom.name()

        return [{
            'uuid': domain.UUIDString(),
            'name': domain_name(domain),
            'active': domain.isActive(),
            'temporary': domain.name().startswith('fc-')
        } for domain in domains]

    def session_start(self, identifier):
        """
        Start session in virtual machine
        """
        self._connect()
        # Get machine by its identifier
        origdomain = self.conn.lookupByUUIDString(identifier)

        # Generate new domain description modifying original XML to use qemu -snapshot command line
        newxml = self._generate_new_domain_xml(origdomain.XMLDesc())

        # Create and run new domain from new XML definition
        self._last_started_domain = self.conn.createXML(newxml)

        # Get spice host and port
        spice_host, spice_port = self._get_spice_parms(self._last_started_domain)

        # Create tunnel
        connection_port, tunnel_pid = self._open_ssh_tunnel(spice_host, spice_port)

        # Make it transient inmediately after started it
        self._undefine_domain(self._last_started_domain)

        # Return identifier and spice URI for the new domain
        return (self._last_started_domain.UUIDString(), connection_port, tunnel_pid)

    def session_stop(self, identifier, tunnel_pid=None):
        """
        Stops session in virtual machine
        """
        if tunnel_pid is not None:
            # Kill ssh tunnel
            # FIXME: Test pid belonging to ssh
            try:
                os.kill(tunnel_pid, signal.SIGKILL)
            except:
                pass
        self._connect()
        # Get machine by its uuid
        self._last_stopped_domain = self.conn.lookupByUUIDString(identifier)
        # Destroy domain
        self._last_stopped_domain.destroy()
        # Undefine domain
        self._undefine_domain(self._last_stopped_domain)
