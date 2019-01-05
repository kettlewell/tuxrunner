#!/usr/bin/env python3
"""Command line utility for quickly managing devices through SSH with some
    super cool & handy features.
    Heavily borrowed from tuxlabs.

    Notes:  # Removing any password auth components. This should only be usable with keys.
            # Should handle proxy through new sao hosts
            # Removing any sudo components. Commands should generally be run as yourself.

            Control Path Doesn't work yet ( upcoming in a new version of paramiko )
            RSA Auth Doesn't work as expected ( sorry NX, maybe control path will fix that )

    TODO:
            hard-coded paths/files need input / env variables.
            clean up command line args to match old host-check.sh
            convert post-verify.sh into post-verify.py
            create args as shortcuts to certain commands ( post-verify.py )
            read remote-scripts from a known location ( ENV var? )
            Create manifest info.
            Better "RESULT" Logging ... without losing INFO, etc.
            Consider JSON for output.
            cleanup imports
            investigate if threading / worker pools / other options work as intended.
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

# Command
parser.add_argument('-c', action="store", dest="commandString", required=False,
                    help="Command to run")

# Script -- Probably need to specify script type ( py, sh, awk, etc )
parser.add_argument('-cf', action="store", dest="commandFile", required=False,
                    help="Specify a 'command file' full of commands to run on "
                    "selected machine(s)")

# Timeouts
parser.add_argument('-ct', action="store", dest="connectTimeout",
                    required=False, help="SSH connect timeout to hosts "
                    "in seconds: default (10)")
parser.add_argument('-cmdt', action="store", dest="cmdTimeout", required=False,
                    help="Timeout for how long to let commands run: "
                    "default (60)")

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
    'created',
    'relativeCreated',
    'msecs',
    'stack_info',
    'exc_info',
    'msg',
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

    # SET USERNAME  ##
    siteUser = ''
    if args.siteUser:
        siteUser = args.siteUser
    elif 'LOGNAME' in os.environ:
        siteUser = os.environ["LOGNAME"]
    elif 'USER' in os.environ:
        siteUser = os.environ["USER"]
    else:
        siteUser = ''

    return (hostFilePath, connectTimeout,
            cmdTimeout, workers, siteUser)


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

    logger.debug("Checking custom_format")
    logger.debug(custom_format)

    return logfilePath


def run_cmds(ssh, cmds, hostname, cmdTimeout):
    try:
        for cmd in cmds:
            logger.debug('[DEBUG] - %s: %s' % (hostname, cmd))
            (stdin, stdout, stderr) = ssh.exec_command(cmd, cmdTimeout)
            logger.debug('%s: [SENT] "%s"' % (hostname, cmd))

            for line in stdout.readlines():
                line = line.rstrip()
                logger.info({"hostname": hostname, "cmd": cmd, "cmd_stdout": line})

            # stderr
            for line in stderr.readlines():
                line = line.rstrip()
                logger.error({"hostname": hostname, "cmd": cmd, "cmd_stdout": line})
    except Exception as e:
        logger.exception(e, exc_info=True)
        raise Exception(e)

    logger.debug("ssh closed")
    ssh.close()


def ssh_to_host(hosts, connectTimeout, cmdTimeout):
    for i in range(workers):
        t = threading.Thread(target=worker,
                             args=(siteUser,
                                   connectTimeout,
                                   cmdTimeout))
        t.daemon = True
        t.start()

    for hostname in hosts:
        if hostname is not None:
            hostname = hostname.rstrip()
            q.put(hostname)

    q.join()


def worker(siteUser, connectTimeout, cmdTimeout):
    while True:
        try:
            hostname = q.get()
        except Exception as e:
            logger.exeception(e, exc_info=True)
        else:
            node_shell(hostname, siteUser,
                       connectTimeout, cmdTimeout)
            q.task_done()


def node_shell(hostname, siteUser, connectTimeout, cmdTimeout):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_config = paramiko.SSHConfig()

    user_config_file = os.path.expanduser("~/.ssh/config")
    if os.path.exists(user_config_file):
        with open(user_config_file) as f:
            ssh_config.parse(f)

    identityFile = None
    cfg = {'hostname': hostname, 'username': siteUser, 'identityfile': identityFile}

    user_config = ssh_config.lookup(cfg['hostname'])

    logger.debug('SSH Config: {}'.format(user_config))

    for k in ('hostname', 'username', 'identityfile'):
        if k in user_config:
            cfg[k] = user_config[k]

    if 'proxycommand' in user_config:
        cfg['sock'] = paramiko.ProxyCommand(user_config['proxycommand'])
        logger.debug('sock:   {}'.format(cfg['sock']))

#  TODO:  combine these two into a single ssh.connect statement by
#         initializing things to None default types
    try:
        if 'sock' not in cfg:
            logger.debug('Attempting: %s, %s, %s, proxy disabled' %
                         (hostname, siteUser, connectTimeout))
            ssh.connect(cfg['hostname'],
                        username=cfg['username'],
                        password=None,
                        timeout=connectTimeout,
                        banner_timeout=connectTimeout,
                        look_for_keys=True,
                        allow_agent=True,
                        key_filename=cfg['identityfile'])
            logger.debug('Connected: {0}, {1}, {2}, proxy disabled'
                         .format(hostname, siteUser, connectTimeout))
        else:
            logger.debug('Attempting: {0}, {1}, {2}, proxy enabled'
                         .format(cfg['hostname'], cfg['username'],
                                 connectTimeout))
            proxySock = cfg['sock']

            ssh.connect(cfg['hostname'],
                        username=cfg['username'],
                        password=None,
                        timeout=connectTimeout,
                        banner_timeout=connectTimeout,
                        sock=proxySock,
                        look_for_keys=True)

            logger.debug('Connected: {0}, {1}, {2}, proxy enabled'
                         .format(cfg['hostname'], cfg['username'],
                                 connectTimeout))

        if args.commandFile:
            try:
                # cmds = open(args.commandFile)
                # cmds = [cmd.strip() for cmd in cmds]

                # Setup sftp connection and transmit this script
                logger.debug("About to open SFTP ... ")
                sftp = ssh.open_sftp()
                sftp.put("/Users/mkettlewell/ssh_test.py", '/tmp/ssh_test.py')
                sftp.close()

                logger.debug("Closed the SFTP Connection ... ")
                # Run the transmitted script remotely without args and show its output.
                # SSHClient.exec_command() returns the tuple (stdin,stdout,stderr)
                logger.debug("About to execute remote script... ")
                (stdin, stdout, stderr) = \
                    ssh.exec_command('sudo python /tmp/ssh_test.py blah')

                # stderr
                for line in stderr.readlines():
                    line = line.rstrip()
                    logger.info('[RESULT - STDERR] - %s' % (line))

                # stdout
                for line in stdout.readlines():
                    line = line.rstrip()
                    logger.info('[RESULT - STDOUT] - %s' % (line))
            except Exception as e:
                logger.error(e, exc_info=True)
        else:
            cmd = args.commandString
            cmds = [cmd]
            logger.debug('About to run_cmds')
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
            # logger.info('[PARAM SET] - SELECTING ALL HOSTS')
            logger.info({"param": "[PARAM SET] - Selecting ALL Hosts {0}"
                         .format(hostFilePath)})
        else:
            hostMatch = args.hostMatch
            for host in hosts:
                if re.search(hostMatch, host):
                    selected_hosts.append(host)
            logger.info({"param": "[PARAM SET] - FILTERING ONLY HOSTNAMES MATCHING {0}"
                        .format(hostMatch)})
    else:
        logger.error('{0} does not exist ! You must create it !'
                     .format(hostFilePath))
        exit()

    logger.info('[PARAM SET] - {0} HOSTS HAVE BEEN SELECTED'
                .format(len(selected_hosts)))

    return selected_hosts


def list_hosts_and_exit(hostlist):
    for host in hostlist:
        host = host.rstrip()
        logger.info(host)
    if len(hostlist) == 1:
        logger.info("There was {0} host listed.".format(len(hostlist)))
    else:
        logger.info("There were {0} hosts listed.".format(len(hostlist)))
    exit()


if __name__ == "__main__":
    (hostFilePath, connectTimeout, cmdTimeout, workers, siteUser) =\
        check_args_and_set_default(args)

    if args.sudo:
        logger.info('[RESULT] - Setting sudo')
        SUDO = 'sudo'
    else:
        logger.info('[RESULT] -  Unsetting sudo')
        SUDO = ''

    logfilePath = create_log(logger)
    logger.info("[PARAM SET] - LOGFILE IS %s" % logfilePath)

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
                logger.info("[PARAM SET] - USER IS {0}".format(siteUser))
                logger.info("[PARAM SET] - SSH CONNECT TIMEOUT IS {} SECONDS"
                            .format(connectTimeout))
                logger.info("[PARAM SET] - THREADS IS {0}".format(workers))

                if args.sudo:
                    SUDO = "sudo"
                    logger.info("[PARAM SET] - SUDO ACTIVATED")
                else:
                    SUDO = ''
                    logger.info("[PARAM SET] - USERMODE ACTIVATED ( No Sudo ) ")

                # # Magic that breaks apart your host list chunks of X.
                # # if divider is 0, all hosts will be executed.
                # if not divider == 0:
                #     chunks = list(itertools.zip_longest(*[iter(selected_hosts)]*divider))
                #     logger.info("[PARAM SET] - DIVIDER IS {} CREATING {} "
                #                 "CHUNKS".format(divider, len(chunks)))
                # else:
                #     chunks = [selected_hosts]
                #     logger.info("[PARAM SET] - TURBO MODE ENABLED - "
                #                 "CHUNKING IS DISABLED")

                # start timer ##
                stime = time.time()

                q = queue.Queue()

                logger.info("[PARAM SET] - TURBO MODE ENABLED - "
                            "CHUNKING IS DISABLED")
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
                logger.info('[SUMMARY] - %s' % (summary))
                if len(failed_logins) > 0:
                    for failed_host in failed_logins:
                        logger.info('[FAILED] - to login to: {}'
                                    .format(failed_host))

                logger.info("[LOG] - Your logfile can be viewed @ {}"
                            .format(logfilePath))
        else:
            parser.print_help()
            logger.error("Either -l (list hosts only) or -c (Run command)"
                         "or -cf (Run command file) is required.")
    except KeyboardInterrupt:
        sys.exit(0)
