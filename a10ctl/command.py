#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import base64

import logging
import logging.handlers as handlers
import os
import re
import sys
import time

import datetime

import acos_client.errors as acos_errors
import getpass
from cryptography.fernet import Fernet

ENC_KEY = 'rhd29NyNcdDqiMLi7NWZHGrNf1TMWzaHiBqEuXpMCN0='

STATUS = {
    0: 'Down',
    '0': 'Down',
    1: 'Up',
    '1': 'Up'
}

PORT_STATUS = {
    0: 'Disabled',
    1: 'Running',
    2: 'Down'
}

ENABLE_STATUS = {
    0: 'Disabled',
    1: 'Enabled',
}

LB_METHODS = ('RoundRobin', 'WeightedRoundRobin', 'LeastConnection', 'WeightedLeastConnection',
              'LeastConnectionOnServicePort', 'WeightedLeastConnectionOnServicePort', 'FastResponseTime',
              'LeastRequest', 'StrictRoundRobin', 'StateLessSourceIPHash', 'StateLessSourceIPHashOnly',
              'StateLessDestinationIPHash', 'StateLessSourceDestinationIPHash', 'StateLessPerPacketRoundRobin',)

CONFIGS = ['./.a10.conf', os.path.expanduser('~') + '/.a10.conf', '/etc/.a10.conf']

try:
    import acos_client
except ImportError:
    sys.stderr.write('acos-client library is missing. Exiting...\n')
    sys.exit(1)

# Python2/3 compatibility
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

# Fix annoying httplib logs
import httplib

httplib.HTTPConnection.debuglevel = 0

logger = logging.getLogger(__name__)


class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    '''
    Handler for logging to a set of files, which switches from one file
    to the next when the current file reaches a certain size, or at certain
    timed intervals
    '''

    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None,
                 delay=0, when='h', interval=1, utc=False):
        # If rotation/rollover is wanted, it doesn't make sense to use another
        # mode. If for example 'w' were specified, then if there were multiple
        # runs of the calling application, the logs from previous runs would be
        # lost if the 'w' is respected, because the log file would be truncated
        # on each run.
        if maxBytes > 0:
            mode = 'a'
        handlers.TimedRotatingFileHandler.__init__(
            self, filename, when, interval, backupCount, encoding, delay, utc)
        self.maxBytes = maxBytes

    def shouldRollover(self, record):
        '''
        Determine if rollover should occur.

        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.
        '''
        if self.stream is None:  # delay was set...
            self.stream = self._open()
        if self.maxBytes > 0:  # are we rolling over?
            msg = '%s\n' % self.format(record)
            self.stream.seek(0, 2)  # due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0


class CommandNotFound(Exception):
    pass


def gettable(headers, data):
    from terminaltables import SingleTable

    table = SingleTable([headers] + data)
    table.inner_heading_row_border = False
    table.inner_column_border = False
    table.outer_border = False

    return table


class A10(object):
    def __init__(self, host, username, password, partition='shared', session_id=None, timeout=None):
        self.host = host
        self.username = username
        self.password = password
        self.partition = partition
        self.client = acos_client.Client(self.host, acos_client.AXAPI_21,
                                         self.username, self.password, timeout=timeout)
        if session_id is not None:
            self.client.session.session_id = session_id
            self.client.session_retries = 0
            try:
                self.client.system.partition.active(args.partition)
            except acos_errors.InvalidSessionID, ex:
                raise Exception('Session has expired. Please re-login')

        self.set_partition(self.partition, force=True)

    def server_login(self):
        return self.client.session.session_id

    def __del__(self):
        self.client.session.close()

    def callMethod(self, command, **args):
        func = getattr(self, command, None)
        if not func:
            raise CommandNotFound('Command %s is not a valid command' % command)
        fvars = list(func.func_code.co_varnames[:func.func_code.co_argcount])
        fvars.remove('self')
        return func(*map(args.get, fvars))

    def set_partition(self, partition, force=False):
        logger.info('Changing active partition to %s' % partition)
        self.client.system.partition.active(partition, force)
        self.partition = partition

    def server_command(self, server, action, groups=False, services=False, vservers=False, ports=None, all=False,
                       timeout=120, wait=False):
        server_info = self.client.slb.server.get(server)['server']
        if all:
            groups = services = vservers = True

        if action == 'status':
            info = '''
Name: {}
IP: {}
Status: {}
Weight: {}
Ports: {}'''.format(server_info['name'], server_info['host'], STATUS[server_info['status']], server_info['weight'],
                    ', '.join(
                        ['{{{}/{}}}'.format(p['port_num'], PORT_STATUS[p['status']]) for p in server_info['port_list']])
                    )
            if groups or services or vservers:
                groups_info = self.client.slb.service_group.all()['service_group_list']
                groups_members = [group['name']
                                  for group in groups_info
                                  for member in group['member_list']
                                  if member['server'] == server_info['name']]
                if groups:
                    info += '\nMember Of: {}'.format(', '.join(groups_members))

                if services:
                    services_info = self.client.slb.virtual_service.all()['virtual_service_list']
                    services_members = [
                        {'port': service['port'], 'name': service['name'], 'address': service['address'],
                         'status': STATUS[service['status']]}
                        for service in services_info
                        if service['service_group'] in groups_members
                        ]

                    info += '\nServices: {}'.format(', '.join(['{name} ({address}:{port}/{status})'.format(**s)
                                                               for s in services_members]))

                if vservers:
                    vservers_info = self.client.slb.virtual_server.all()['virtual_server_list']
                    vservers_members = [
                        {'port': vport_list['port'], 'name': vserver['name'], 'address': vserver['address'],
                         'status': STATUS[vserver['status']]}
                        for vserver in vservers_info
                        for vport_list in vserver['vport_list']
                        if vport_list['service_group'] in groups_members
                        ]
                    info += '\nVirtual Servers: \n{}'.format(
                        ', \n'.join(['{name} ({address}:{port}/{status})'.format(**v) for v in vservers_members]))
            logger.info(info)

        elif action == 'enable':
            if server_info['status'] == 1:
                logger.info('Server is already enabled')
            else:
                self.client.slb.server.update(server_info['name'], server_info['host'], status=1)
                logger.info('Server {} is now enabled'.format(server))
        elif action == 'disable':
            if server_info['status'] == 0:
                logger.info('Server is already disabled')
            else:
                self.client.slb.server.update(server_info['name'], server_info['host'], status=0)
                logger.info('Server {} is now disabled'.format(server))
                if wait:
                    self.server_connections_wait_zero(server, None, timeout)

        elif action == 'enableport' or action == 'disableport':
            ports_info = server_info['port_list']
            ports_status = {p['port_num']: {'status': p['status'], 'protocol': p['protocol']} for p in ports_info}
            port_list = list()
            new_status = 0 if action == 'disableport' else 1
            new_status_text = 'disabled' if action == 'disableport' else 'enabled'

            for port in map(int, ports):
                if port not in ports_status:
                    raise Exception('Port {} is not defined for server {}'.format(port, server))
                if ports_status[port]['status'] == new_status:
                    logger.info('Port {} is already {}'.format(port, new_status_text))
                else:
                    port_list.append(
                        {'port_num': port, 'status': new_status, 'protocol': ports_status[port]['protocol']})

            if port_list:
                self.client.slb.server.update(server_info['name'], server_info['host'], status=server_info['status'],
                                              port_list=port_list)
                if action == 'disableport' and wait:
                    self.server_connections_wait_zero(server, ports, timeout)

            logger.info('Port(s) ({}) for server {} are now {}'.format(', '.join(ports), server, new_status_text))

    def server_list(self, nfilter=None):
        logger.info('Listing configured servers [filter: %s]' % nfilter)
        servers = []
        header = ('Name', 'IP', 'Ports', 'Status')
        server_data = list()

        for server in sorted(self.client.slb.server.all()['server_list'], key=lambda k: k['name']):
            if nfilter and not (re.match(nfilter, server['name']) or nfilter in server['name']):
                continue
            servers.append(server)
            # logger.info(' %s [%s:%s]:\t%s' % (server['name'],
            #                                  server['host'], '{%s}' % ','.join([str(p['port_num']) for p in
            #                                                                     server['port_list']]),
            #                                  STATUS[server['status']]))
            server_data.append([
                server['name'],
                server['host'],
                ',\n'.join(['(%s/%s)' % (p['port_num'], PORT_STATUS[p['status']]) for p in server['port_list']]),
                STATUS[server['status']]
            ])
        table = gettable(header, server_data)
        logger.info(table.table)
        return servers

    def groups_list(self, nfilter=None, members=False):
        logger.info('Listing configured servers [filter: %s]' % nfilter)
        groups = []

        for group in sorted(self.client.slb.service_group.all()['service_group_list'], key=lambda k: k['name']):
            if nfilter and not (re.match(nfilter, group['name']) or nfilter in group['name']):
                continue
            groups.append(group)
            if members:
                members_details = '\n\tMembers:\n' + '\n'.join(
                    ['\t\t%20s:%d (Status: %s)' % (m['server'], m['port'], ENABLE_STATUS[m['status']]) for m in group['member_list']])
            else:
                members_details = ''
            logger.info('%s (%d Members, Algo: %s) %s' % (group['name'],
                                                         len(group['member_list']),
                                                         LB_METHODS[group['lb_method']],
                                                         members_details))
        return groups

    def server_backup(self, filename):
        logger.info('Backing up configuration for server %s into %s' %
                    (self.host, filename))
        if os.path.exists(os.path.expanduser(filename)):
            raise Exception('Backup file already exists. Skipping operation!')

        with open(filename, 'wb') as f:
            f.write(self.client.system.backup())
            f.flush()

    def add_server(self, **kwargs):
        logger.error('Not implemented')

    def del_server(self, **kwargs):
        logger.error('Not implemented')

    def server_up(self, server):
        logger.info('Marking server %s as UP' % server)
        server_info = self.client.slb.server.get(server)['server']
        return self.client.slb.server.update(server_info['name'],
                                             server_info['host'], status=1)

    def server_down(self, server):
        logger.info('Marking server %s as DOWN' % server)
        server_info = self.client.slb.server.get(server)['server']
        return self.client.slb.server.update(server_info['name'],
                                             server_info['host'], status=0)

    def server_connections_wait_zero(self, server, ports=None, timeout=120):
        start_time = datetime.datetime.now()
        connections_count = -1
        while connections_count != 0 and (datetime.datetime.now() - start_time).total_seconds() < timeout:
            server_stats = self.client.slb.server.fetchStatistics(server)['server_stat']
            if ports is None:
                connections_count = server_stats['cur_conns']
            else:
                connections_count = 0
                for port_stats in server_stats['port_stat_list']:
                    if str(port_stats['port_num']) in ports:
                        connections_count += port_stats['cur_conns']
            if connections_count != 0:
                logger.info('Current connections: %s' % connections_count)
                time.sleep(1)

        if connections_count != 0:
            logger.error('Failed to wait for Zero Connections. Current connections: %s. %s' % (
                connections_count, '' if ports is None else ' Ports:' + ','.join(ports)))
            raise Exception('Timeout error')
        else:
            logger.info('No more connections to server.%s' % ('' if ports is None else ' Ports: ' + ','.join(ports)))

    def server_connections(self, server, watch=False, interval=10, ports=None):
        server_stats = self.client.slb.server.fetchStatistics(server)['server_stat']

        header = ('Server Name', 'Status', 'Port', 'Conn', 'Reqs', 'T. Conn', 'T. Reqs', 'T. Success')

        first = True
        try:
            while watch or first:
                stats_data = list()
                if first:
                    first = False
                else:
                    delta = interval
                    while delta:
                        time.sleep(1)
                        delta -= 1
                    server_stats = self.client.slb.server.fetchStatistics(server)['server_stat']
                    print('\033c')
                if ports:
                    for port_stats in server_stats['port_stat_list']:
                        if 'any' in ports or str(port_stats['port_num']) in ports:
                            stats_data.append(
                                [
                                    server_stats['name'],
                                    PORT_STATUS[port_stats['status']],
                                    port_stats['port_num'],
                                    port_stats['cur_conns'],
                                    port_stats['cur_reqs'],
                                    port_stats['tot_conns'],
                                    port_stats['total_reqs'],
                                    port_stats['total_reqs_succ']
                                ])
                else:
                    stats_data.append(
                        [
                            server_stats['name'],
                            STATUS[server_stats['status']],
                            'Any',
                            server_stats['cur_conns'],
                            server_stats['cur_reqs'],
                            server_stats['tot_conns'],
                            server_stats['total_reqs'],
                            server_stats['total_reqs_succ']
                        ])

                table = gettable(header, stats_data)
                logger.info(table.table)
        except KeyboardInterrupt as ex:
            return stats_data

    def server_stats(self, server, stat=None):
        # server_info = self.client.slb.server.get(server)['server']
        server_stats = self.client.slb.server.fetchStatistics(server)['server_stat']

        if stat and not stat in server_stats:
            raise Exception('Unknown statistic name %s' % stat)
        for s in server_stats:
            if s == 'port_stat_list': continue
            if stat and not s == stat:
                continue
            logger.info(' * %s: %s' % (s, server_stats[s]))

        return server_stats

    def server_status(self, server):
        server_info = self.client.slb.server.get(server)['server']
        logger.info('Server %s status: %s' % (
            server,
            STATUS['%s' % server_info['status']]
        ))
        stats = self.client.slb.server.fetchStatistics(server)['server_stat']
        logger.info('Current connection total: %s' % stats['cur_conns'])
        return server_info['status']


# Helper functions
##################

def log_setup(log_file=None):
    formatter = logging.Formatter(
        '%(message)s')
    formatter.converter = time.gmtime  # if you want UTC time
    logger = logging.getLogger()
    if log_file:
        log_handler = SizedTimedRotatingFileHandler(
            log_file, maxBytes=52428800, backupCount=5,
            when='s', interval=86400,
            # encoding='bz2',  # uncomment for bz2 compression
        )
    else:
        log_handler = logging.StreamHandler(sys.stdout)

    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    return logger


def parse_arguments(defaults):
    parser = argparse.ArgumentParser(description='Manage servers within A10 load balancers')
    subparsers = parser.add_subparsers(title='subcommands')
    parser.add_argument('-H', '--host', help='The name/ip of the A10',
                        type=str)
    parser.add_argument('-u', '--username', help='A10 username',
                        type=str, default=None)
    parser.add_argument('-p', '--password', help='A10 password',
                        type=str, default=None)
    parser.add_argument('-k', '--ask-pass', help='Ask for username/password if not provided',
                        default=False, action='store_true')
    parser.add_argument('-P', '--partition', help='A10 partition',
                        type=str, default='shared')
    parser.add_argument('-S', '--session_id', help='A10 session id',
                        type=str, default=None)
    parser.add_argument('-d', '--debug', help='Enable debugging messages',
                        default=False, action='store_true')
    parser.add_argument('-l', '--logfile', help='Specify log file', default=None, type=str)
    parser.add_argument('--traceback', help='Print traces for exceptions',
                        default=False, action='store_true')
    parser.set_defaults(**defaults)

    # # up
    # parser_up = subparsers.add_parser('up', description='Enable an LB server')
    # parser_up.add_argument('server', help='The server name')
    # parser_up.set_defaults(command='server_up')
    #
    # # down
    # parser_down = subparsers.add_parser('down', description='Disable an LB server')
    # parser_down.add_argument('server', help='The server name')
    # parser_down.set_defaults(command='server_down')

    # status
    parser_status = subparsers.add_parser('status', description='Check status of a server')
    parser_status.add_argument('server', help='Server name',
                               type=str, default=None)
    parser_status.set_defaults(command='server_status')

    # stats
    parser_stats = subparsers.add_parser('stats', description='Check statistics for a server')
    parser_stats.add_argument('server', help='The server name')
    parser_stats.add_argument('stat', help='Stat to retrieve', nargs='?',
                              type=str)
    parser_stats.set_defaults(command='server_stats')

    # connections
    parser_stats = subparsers.add_parser('connections', description='Get connection details for a server')
    parser_stats.add_argument('server', help='The server name')
    parser_stats.add_argument('--port', '-p', help='Ports to get the connection detail for. Use any for all port',
                              action='append', dest='ports')
    parser_stats.add_argument('--watch', '-w', help='Watch the connections in a loop',
                              action='store_true', default=False)
    parser_stats.add_argument('--interval', '-i', help='Interval in seconds to wait before polling stats again',
                              default=5, type=int)
    parser_stats.set_defaults(command='server_connections')

    # zeroconnections
    parser_stats = subparsers.add_parser('zeroconnections', description='Check statistics for a server')
    parser_stats.add_argument('server', help='The server name or IP')
    parser_stats.add_argument('--port', '-p', help='Ports to get the connection detail for', action='append',
                              dest='ports')
    parser_stats.add_argument('--timeout', '-t', help='Timeout for waiting', default=120, type=int)
    parser_stats.set_defaults(command='server_connections_wait_zero')

    # server
    parser_server = subparsers.add_parser('status', description='Get info of server')
    parser_server.add_argument('--groups', help='Get groups this server is part of', action='store_true', default=False)
    parser_server.add_argument('--services', help='Get services this server is part of', action='store_true',
                               default=False)
    parser_server.add_argument('--vservers', help='Get virtual servers this server is part of', action='store_true',
                               default=False)
    parser_server.add_argument('--all', help='Get all information', action='store_true',
                               default=False)
    parser_server.add_argument('server', help='The server name or IP')
    parser_server.set_defaults(command='server_command', action='status')

    parser_server = subparsers.add_parser('enable', description='Enable a server')
    parser_server.add_argument('server', help='The server name or IP')
    parser_server.set_defaults(command='server_command', action='enable')

    parser_server = subparsers.add_parser('disable', description='Disable a server')
    parser_server.add_argument('server', help='The server name or IP')
    parser_server.add_argument('--wait', help='Wait for Zero connections to server on LB after disabling',
                               action='store_true')
    parser_server.add_argument('--timeout', help='Timeout to wait for zero connection. Default 120 sec', default=120,
                               type=int)
    parser_server.set_defaults(command='server_command', action='disable')

    parser_server = subparsers.add_parser('disableports', description='Disable ports on the server')
    parser_server.add_argument('server', help='The server name or IP')
    parser_server.add_argument('--wait', help='Wait for Zero connections to specified ports on LB after disabling',
                               action='store_true')
    parser_server.add_argument('--timeout', help='Timeout to wait for zero connection. Default 120 sec', default=120,
                               type=int)

    parser_server.add_argument('ports', nargs='+',
                               help='Ports to disable. Multiple ports with spaces. Use any for disabling all ports')
    parser_server.set_defaults(command='server_command', action='disableport')

    parser_server = subparsers.add_parser('enableports', description='Enable ports on the server')
    parser_server.add_argument('server', help='The server name or IP')
    parser_server.add_argument('ports', nargs='+',
                               help='Ports to Enable. Multiple ports with spaces. Use any for Enabling all ports')
    parser_server.set_defaults(command='server_command', action='enableport')

    # servers
    parser_list = subparsers.add_parser('servers', description='List servers')
    parser_list.add_argument('nfilter', help='Regex filter for server names',
                             default=None, nargs='?', type=str)
    parser_list.set_defaults(command='server_list')

    # groups
    parser_groups = subparsers.add_parser('groups', description='List groups')
    parser_groups.add_argument('--members', help='List member details',
                               action='store_true', default=False)
    parser_groups.add_argument('nfilter', help='Regex filter for group names',
                               default=None, nargs='?', type=str)
    parser_groups.set_defaults(command='groups_list')

    # backup
    parser_backup = subparsers.add_parser('backup', description='List servers')

    parser_backup.add_argument('filename', help='Name of the backup file',
                               default='system_backup_%s.tar.gz' % time.strftime('%Y%m%d-%H%M%S'),
                               nargs='?', type=str)
    parser_backup.set_defaults(command='server_backup')

    parser_login = subparsers.add_parser('login', description='Login to A10 servers and generate SESSION_ID')
    parser_login.set_defaults(command='server_login')

    parser_config = subparsers.add_parser('config', description='Create config file for A10')
    parser_config.set_defaults(command='server_config')

    return parser


# Script Logic
##############

def main():
    ''' Error codes:
    * 0: OK
    * 1: Exception was thrown
    '''
    global logger, args

    confp = argparse.ArgumentParser(add_help=False)
    confp.add_argument('-c', '--config', metavar='FILE',
                       default=None, help='configuration file')
    confp.add_argument('-L', '--profile', default='root', help='Profile section in config file')

    cargs, remaining_argv = confp.parse_known_args()
    defaults = {}

    if not remaining_argv == ['config']:
        if not cargs.config:
            if os.getenv('A10_CONFIG', None):
                cargs.config = os.getenv('A10_CONFIG')
            else:
                for conf_file in CONFIGS:
                    if os.path.isfile(conf_file):
                        cargs.config = conf_file
                        break

        cargs.profile = cargs.profile or os.getenv('A10_PROFILE')

        if cargs.config:
            try:
                rawconf = open(os.path.expanduser(cargs.config), 'r')
                config = configparser.ConfigParser()
                config.readfp(rawconf)

                if config.has_section(cargs.profile):
                    defaults = dict(config.items(cargs.profile))
                    if 'password' in defaults:
                        f = Fernet(ENC_KEY)
                        defaults['password'] = f.decrypt(defaults['password'])

                else:
                    defaults = {}

            except Exception as e:
                sys.stderr.write("Warning: Couldn't parse config file %s: %s\n" % (
                    cargs.config, e))
                defaults = {}
                # sys.exit(1 )

        for param in ['host', 'username', 'password', 'partition', 'session_id']:
            env_key = 'A10_' + param.upper()
            if os.getenv(env_key, None):
                defaults[param] = os.getenv(env_key, None)
    else:
        defaults = {}

    parser = parse_arguments(defaults)
    args = parser.parse_args(remaining_argv)

    def server_config():
        config_file = raw_input(
            'Where to create the config file?\n\n\t0 - ./.a10.conf\n\t1 - ~/.a10.conf\n\t2 - /etc/.a10.conf\n\n[0]: ') or '0'

        if config_file in ['0', '1', '2']:
            config_file = CONFIGS[int(config_file)]
        elif config_file not in CONFIGS:
            sys.stderr.write('Invalid config file specified')
            sys.exit(1)

        profile = 'root'
        profile = raw_input('Enter profile name [root]: ') or profile

        if not os.path.isfile(config_file):
            with open(config_file, 'a'):
                pass

        try:
            rawconf = open(os.path.expanduser(config_file), 'r')
            config = configparser.ConfigParser()
            config.readfp(rawconf)
            defaults = {}
            if config.has_section(profile):
                defaults = dict(config.items(profile))

        except Exception as e:
            defaults = dict()
            pass

        host = defaults.get('host', '')
        username = defaults.get('username', '')
        password = defaults.get('password', '')
        partition = defaults.get('partition', 'shared')

        host = raw_input('Enter host name [{}]: '.format(host)) or host
        username = raw_input('Enter username [{}]: '.format(username)) or username
        password_new = getpass.getpass('Enter password (Leave blank to save existing) [****]: ')

        partition = raw_input('Enter partition [{}]: '.format(partition)) or partition

        if password_new:
            f = Fernet(ENC_KEY)
            password_new_enc = f.encrypt(password_new)
            password = password_new_enc

        if not config:
            pass

        if not config.has_section(profile):
            config.add_section(profile)

        config.set(profile, 'host', host)
        config.set(profile, 'username', username)
        config.set(profile, 'password', password)
        config.set(profile, 'partition', partition)

        with open(os.path.expanduser(config_file), 'wb') as config_file_update:
            config.write(config_file_update)

        logger.info('Configuration saved!')

    # Fix annoying loggers from requests/acos_client
    for l in logging.getLogger().manager.loggerDict:
        mlog = logging.getLogger(l)
        mlog.setLevel(logging.ERROR)
        mlog.propagate = False

    logging.getLogger('acos_client').setLevel(logging.ERROR)
    logger = log_setup(args.logfile)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.command == 'server_config':
        server_config()
        sys.exit(0)

    if not args.host or not args.command:
        parser.error('No hosts specified')
        sys.exit()

    try:
        # args.host = args.host or os.getenv('A10_HOST')
        # args.username = args.username or os.getenv('A10_USERNAME')
        # args.password = args.password or os.getenv('A10_PASSWORD')
        # args.partition = args.partition or os.getenv('A10_PARTITION')

        if args.command == 'server_login':
            logger.setLevel(logging.ERROR)
            args.session_id = None

        if not args.password and not args.session_id:
            if args.ask_pass:
                if not args.username:
                    args.username = getpass.getpass('A10 Username: ')
                args.password = getpass.getpass('A10 Password: ')
        if not (args.password or args.username) and not args.session_id:
            raise Exception('Either session_id or username and password is required')

        a10 = A10(host=args.host, username=args.username,
                  password=args.password, partition=args.partition, session_id=args.session_id, timeout=120)
        rc = a10.callMethod(**vars(args))
        if args.command == 'server_login':
            print rc
    except CommandNotFound as e:
        parser.error('Command %s is not valid' % args.command)
        sys.exit(1)
    except Exception as e:
        logger.error(e, exc_info=args.traceback)
        sys.exit(1)


if __name__ == '__main__':
    main()
