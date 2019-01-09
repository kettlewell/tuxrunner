#!/usr/bin/env python3
"""Command line utility for quickly managing devices through SSH with some
    super cool & handy features.
    Heavily borrowed from tuxlabs.


USAGE:

    Notes:

            Control Path Doesn't work yet ( upcoming in a new version of paramiko )
            RSA Auth Doesn't work as expected ( sorry NX, maybe control path will fix that )

    TODO:
            hard-coded paths/files need input / env variables.

            convert post-verify.sh into post-verify.py
            create args as shortcuts to certain commands ( post-verify.py )
            read remote-scripts from a known location ( ENV var? )
            Create manifest info.
            Better "RESULT" Logging ... without losing INFO, etc.
            [ Custom Log Level?  ERR,WARN,INFO,RESULT,INFO,DEBUG ]

    """


# import getpass
import queue
import threading
import argparse
import os.path
import time
import logging
from pythonjsonlogger import jsonlogger
import re
import datetime
import itertools
import sys
import base64
from pprint import pprint
from Crypto.Cipher import AES
from Crypto import Random
import paramiko

# import storePass

__author__ = 'Matt Kettlewell'
__description__ = 'Command line utility for quickly managing devices ' \
                    'through SSH with some super cool & handy features.'
__version__ = '0.0.1'


# # SETUP AVAILABLE ARGUMENTS ##
parser = argparse.ArgumentParser()

# Command ( single simple command)
parser.add_argument('-c', action="store", dest="commandString", required=False,
                    help="Command to run")

# Python Script
# -py /full/path/to/python/script.py
parser.add_argument('-py', action="store", dest="pythonScript", required=False,
                    help="Specify a python script be uploaded and run on "
                    "selected remote host(s)")

# Shell Script
# -sh /ful/path/to/bash/script.sh
parser.add_argument('-sh', action="store", dest="shellScript", required=False,
                    help="Specify a python script be uploaded and run on "
                    "selected remote host(s)")

# Script Files - list of scripts (bash/python  to be uploaded and executed sequentially
# python /full/path/to/python/script.py
# bash /ful/path/to/bash/script.sh
parser.add_argument('-sf', action="store", dest="scriptFile", required=False,
                    help="Specify a 'command file' full of commands to run on "
                    "selected hosts(s)")

# Command File ( File of commands / scripts to upload / execute )
parser.add_argument('-cf', action="store", dest="commandFile", required=False,
                    help="Specify a 'command file' full of commands to run on "
                    "selected hosts(s)")

# Timeouts
parser.add_argument('-ct', action="store", dest="connectTimeout",
                    required=False, help="SSH connect timeout to hosts "
                    "in seconds: default (10)")
parser.add_argument('-cmdt', action="store", dest="cmdTimeout", required=False,
                    help="Timeout for how long to let commands run: "
                    "default (60)")

# Host FQDN
parser.add_argument('-f', action="store", dest="fqdn", required=False,
                    help="Specify fqdn of single host")

# Host IP
parser.add_argument('-i', action="store", dest="ipaddr", required=False,
                    help="Specify IP of single host")

# Host List
parser.add_argument('-hf', action="store", dest="hostFilePath", required=False,
                    help="Specify your own path to a hosts file [defaults to ~/.hostlist.txt]")

# List Hosts
parser.add_argument('-l', action="store_true", dest="listOnly",
                    required=False, help="List all known hosts")

# Logging
parser.add_argument('-lf', action="store", dest="logfile", nargs='?',
                    const="nofile", required=False,
                    help="Turns logging on, can also take logfile "
                    "location as a parameter.")

parser.add_argument('-ll', action="store", dest="logLevel", required=False,
                    help="Set Log Level: DEBUG, INFO (DEFAULT), "
                    "WARNING, ERROR, CRITICAL")

# Paramiko Logging
parser.add_argument('-pl', action="store", dest="paramikoLogLevel",
                    required=False, help="Set Paramiko Log Level: DEBUG, "
                    "INFO, WARNING, ERROR, CRITICAL (DEFAULT)")

# Host Regex
parser.add_argument('-r', action="store", dest="hostMatch", required=False,
                    help="Select Hosts matching supplied pattern")

# Run command as sudo
parser.add_argument('-s', action="store_true", dest="sudo", required=False,
                    help="Run command with sudo (performance is much slower)")

# Number of threads
parser.add_argument('-t', action="store", dest="threads", required=False,
                    help="Number of threads to run, don't get crazy ! "
                    "Increasing threads too much can negatively "
                    "impact performance.")

# Remote Username
parser.add_argument('-u', action="store", dest="siteUser", required=False,
                    help="Specify a username "
                    "(by default I use who you are logged in as)")


args = parser.parse_args()

############
# GLOBAL ##
############

failed_logins = []
successful_logins = []
home_dir = os.path.expanduser("~")
SUDO = ''

#############
# LOGGING ##
#############

# Add RESULT custom log level
RESULT = 25
logging.addLevelName(RESULT, "RESULT")


def result(self, message, *args, **kws):
    self.log(RESULT, message, *args, **kws)


logging.Logger.result = result

#  Debugging ssh stream. (root logger)
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

# Runner Logger
logger = logging.getLogger(__name__)

# Don't propagate logs
logger.propagate = False

# Set default log levels
logger.setLevel(logging.INFO)  # runner
logging.getLogger('paramiko').setLevel(logging.CRITICAL)  # paramiko

# Stream Handling
ch = logging.StreamHandler()

custom_keys = [
    'levelname',
    'asctime',
    'message'
]


# Formatting
def log_format(x): return ['%({0:s})'.format(i) for i in x]


custom_format = ' '.join(log_format(custom_keys))
formatter = jsonlogger.JsonFormatter(custom_format, datefmt='%Y-%m-%d')

# Set runner logger to handle the stream and formatter
ch.setFormatter(formatter)
logger.addHandler(ch)

# change default log levels
if args.logLevel:
    level = logging.getLevelName(args.logLevel)
    logger.setLevel(level)

if args.paramikoLogLevel:
    level = logging.getLevelName(args.paramikoLogLevel)
    logging.getLogger('paramiko').setLevel(level)

# END OF LOGGING AND GLOBALS ###


def check_args_and_set_default(args):
    # SET DEFAULT HOSTS FILE ##
    hostFilePath = "{0}/.hostlist.txt".format(home_dir)
    if args.hostFilePath:
        hostFilePath = args.hostFilePath

    # SET CONNECT TIMEOUT ##
    connectTimeout = 10
    if args.connectTimeout:
        connectTimeout = int(args.connectTimeout)

    # SET CMD TIMEOUT ##
    cmdTimeout = 60
    if args.cmdTimeout:
        cmdTimeout = int(args.cmdTimeout)

    # SET THREADS / WORKERS ##
    workers = 2
    if args.threads:
        workers = int(args.threads)

    return (hostFilePath, connectTimeout,
            cmdTimeout, workers)


def create_log(logger):
    if args.logfile:
        logfile = args.logfile
        logfilePath = os.path.expanduser(logfile)
    else:
        logfile_dir = "{0}/tuxrunner-logs".format(home_dir)
        tstamp = datetime.datetime.now().strftime("%Y-%m-%d.%H.%M.%S")

        if not os.path.exists(logfile_dir):
            os.makedirs(logfile_dir)
        logfilePath = '{0}/tuxrunner.log.{1}'.format(logfile_dir, tstamp)

    fh = logging.FileHandler(logfilePath, "w")
    logger.addHandler(fh)
    formatter = jsonlogger.JsonFormatter(custom_format, datefmt='%Y-%m-%d')
    fh.setFormatter(formatter)

    logger.debug('checking custom format', extra={'debug_extra': {'custom_format': "Checking custom_format"}})
    logger.debug('Grabbed Custom Format Values', extra={'debug_extra': {'custom_format': custom_format}})

    return logfilePath


def run_cmds(ssh, cmds, hostname, cmdTimeout):
    try:
        for cmd in cmds:
            logger.debug({'debug_extra': {'hostname': hostname, 'cmd': cmd}})
            (stdin, stdout, stderr) = ssh.exec_command(cmd, cmdTimeout)
            logger.debug({'debug_extra': {'hostname': hostname, 'cmd': cmd, 'note': 'sent'}})

            for line in stdout.readlines():
                line = line.rstrip()
                msg = {'result': {"hostname": hostname, "cmd": cmd, "cmd_stdout": line}}
                # message = {"hostname": hostname, "cmd": cmd, "cmd_stdout": line}

                logger.result(msg)
                # logger.info(message)
            # stderr
            for line in stderr.readlines():
                line = line.rstrip()
                msg = {'result': {"hostname": hostname, "cmd": cmd, "cmd_stdout": line}}
                logger.result(msg)
    except Exception as e:
        logger.exception(e, exc_info=True)
        raise Exception(e)

    logger.debug({'debug_extra': {'ssh_status': 'ssh closed'}})
    ssh.close()


def ssh_to_host(hosts, connectTimeout, cmdTimeout):
    for i in range(workers):
        t = threading.Thread(target=worker,
                             args=(
                                   connectTimeout,
                                   cmdTimeout))
        t.daemon = True
        t.start()

    for hostname in hosts:
        if hostname is not None:
            hostname = hostname.rstrip()
            q.put(hostname)

    q.join()


def worker(connectTimeout, cmdTimeout):
    while True:
        try:
            hostname = q.get()
        except Exception as e:
            logger.exeception(e, exc_info=True)
        else:
            node_shell(hostname,
                       connectTimeout, cmdTimeout)
            q.task_done()


def node_shell(hostname, connectTimeout, cmdTimeout):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_config = paramiko.SSHConfig()

    user_config_file = os.path.expanduser("~/.ssh/config")
    if os.path.exists(user_config_file):
        with open(user_config_file) as f:
            ssh_config.parse(f)

    identityFile = None
    siteUser = ''
    cfg = {'hostname': hostname, 'user': siteUser, 'identityfile': identityFile}

    user_config = ssh_config.lookup(cfg['hostname'])
    msg = {'debug_extra': {'ssh_config': user_config}}
    logger.debug(msg)

    for k in ('hostname', 'user', 'identityfile'):
        if k in user_config:
            cfg[k] = user_config[k]

    # SET USERNAME  ##
    # use a cli name first, then ssh_config name, then local os username
    if args.siteUser:
        siteUser = args.siteUser
    elif 'user' in user_config:
        siteUser = cfg['user']
    elif 'LOGNAME' in os.environ:
        siteUser = os.environ["LOGNAME"]
    elif 'USER' in os.environ:
        siteUser = os.environ["USER"]
    else:
        siteUser = ''

    msg = {"info_extra": {"user": siteUser}}
    logger.info(msg)
    proxySock = None
    if 'proxycommand' in user_config:
        proxySock = paramiko.ProxyCommand(user_config['proxycommand'])
        logger.debug({'debug_extra': {'sock': proxySock}})

    if 'identityfile' in user_config:
        identityFile = cfg['identityfile']
        logger.debug({'debug_extra': {'identityfile': identityFile}})

#  TODO:  combine these two into a single ssh.connect statement by
#         initializing things to None default types
    try:
        logger.debug({'debug_extra': {'hostname': hostname, 'siteUser': siteUser, 'connectTimeout': connectTimeout, 'note': 'Attempting SSH Connection'}})
        ssh.connect(cfg['hostname'],
                    username=siteUser,
                    password=None,
                    timeout=connectTimeout,
                    banner_timeout=connectTimeout,
                    look_for_keys=True,
                    allow_agent=True,
                    sock=proxySock,
                    key_filename=identityFile)
        logger.debug({'debug_extra': {'hostname': hostname,
                                      'siteUser': siteUser, 'connectTimeout': connectTimeout, 'note': 'SSH Connected'}})

        if args.commandFile:
            try:
                # cmds = open(args.commandFile)
                # cmds = [cmd.strip() for cmd in cmds]

                # Setup sftp connection and transmit this script
                logger.debug({'debug_extra': {"sftp": "About to open SFTP ... "}})
                sftp = ssh.open_sftp()
                sftp.put("/Users/mkettlewell/ssh_test.py", '/tmp/ssh_test.py')
                sftp.close()

                logger.debug({'debug_extra': {"sftp": "Closed the SFTP Connection ... "}})
                # Run the transmitted script remotely without args and show its output.
                # SSHClient.exec_command() returns the tuple (stdin,stdout,stderr)
                logger.debug({'debug_extra': {'executing': "About to execute remote script... "}})
                (stdin, stdout, stderr) = \
                    ssh.exec_command('sudo python /tmp/ssh_test.py blah')

                # stderr
                for line in stderr.readlines():
                    line = line.rstrip()
                    logger.result({'result': {'line': line}})

                # stdout
                for line in stdout.readlines():
                    line = line.rstrip()
                    logger.result({'result': {'line': line}})
            except Exception as e:
                logger.error(e, exc_info=True)
        else:
            cmd = args.commandString
            cmds = [cmd]
            logger.debug({'debug_extra': {'commandString': 'About to run_cmds', 'cmds': cmds}})
            run_cmds(ssh, cmds, hostname, cmdTimeout)

# TODO: create a generic "CMD" string, whether it's a command file,
#       or a cmd, that will call run_cmds ( or a variation of that )

        successful_logins.append(hostname)

    except Exception as e:
        ssh.close()
        logger.exception('EXCEPTION: ssh closed', exc_info=True)
        logger.exception('EXCEPTION: %s: failed to login : %s' % (hostname, e), exc_info=True)
        failed_logins.append(hostname)


def get_hosts(hostFilePath):
    # Expands ~ to users home directory.
    exFilePath = os.path.expanduser(hostFilePath)
    if os.path.exists(exFilePath):
        hosts = open(exFilePath)
        selected_hosts = []
        if not args.hostMatch:
            selected_hosts = list(hosts)
            logger.info({"info_extra": {'all_hosts': hostFilePath}})
        else:
            hostMatch = args.hostMatch
            for host in hosts:
                if re.search(hostMatch, host):
                    selected_hosts.append(host)
            logger.info({"info_extra": {'hostMatch': hostMatch, 'note': "FILTERING ONLY HOSTNAMES MATCHING", 'hosts': hosts}})
    else:
        logger.error('Host Not Exist', extra={'not_exist': {'hostFilePath': hostFilePath, 'note': 'Create File Path'}})
        exit()

    logger.info({'info_extra': {'selected_hosts': selected_hosts, 'num_selected_hosts': len(selected_hosts)}})

    return selected_hosts


def list_hosts_and_exit(hostlist):
    for host in hostlist:
        host = host.rstrip()
        logger.info({'info_extra': {'host': host}})

    logger.result({'result': {'hosts': len(hostlist)}})

    exit()


if __name__ == "__main__":
    (hostFilePath, connectTimeout, cmdTimeout, workers) =\
        check_args_and_set_default(args)

    logfilePath = create_log(logger)
    logger.info({"info_extra": {'type': 'param', "logfilePath": logfilePath}})

    if args.sudo:
        logger.info({"info_extra": {'type': 'param', "sudo": "Sudo Is Set"}})
        SUDO = 'sudo'
    else:
        logger.info({"info_extra": {'type': 'param', "sudo": "Sudo Is Not Used"}})
        SUDO = ''

    try:
        if args.listOnly or args.commandString or args.commandFile:
            # if any of these are true, we will need to get the hosts.
            selected_hosts = get_hosts(hostFilePath)

            if len(selected_hosts) == 0:
                logger.info("No hosts could be found. Ensure you have "
                            "a hosts file and that your regular expression"
                            " is matching correctly if you set one.")
                exit()

            if args.listOnly:
                list_hosts_and_exit(selected_hosts)

            # Execute Command or Script
            else:
                logger.info({'info_extra': {'type': 'param', 'ssh_timeout': connectTimeout}})

                logger.info({'info_extra': {'type': 'param', 'threads': workers}})

                if args.sudo:
                    SUDO = "sudo"
                    logger.info({'info_extra': {'type': 'param', 'sudo': True}})
                else:
                    SUDO = ''
                    logger.info({'info_extra': {'type': 'param', 'sudo': False}})

                # start timer ##
                stime = time.time()

                q = queue.Queue()

                ssh_to_host(selected_hosts,
                            connectTimeout, cmdTimeout)

                # end timer ##
                etime = time.time()
                run_time = int(etime - stime)

                timestamp = str(datetime.timedelta(seconds=run_time))
                summary = "Successfully logged into {0} / {1} hosts and ran your commands in {2} second(s)".format((len(successful_logins)), len(selected_hosts), timestamp)
                if len(successful_logins) == 0:
                    summary = "Failed to login on all {0} hosts."\
                              .format(len(selected_hosts))
                logger.info({'info_extra': {'type': 'summary', 'login_summary': summary}})
                if len(failed_logins) > 0:
                    for failed_host in failed_logins:
                        logger.error({'summary': {'failed_hosts': failed_host}})

                logger.info({'info_extra': {'type': 'summary', 'log_summary': logfilePath}})
        else:
            parser.print_help()
            logger.error("Either -l (list hosts only) or -c (Run command)"
                         "or -cf (Run command file) is required.", {'error_extra': {'args': args}})
    except KeyboardInterrupt:
        sys.exit(0)
