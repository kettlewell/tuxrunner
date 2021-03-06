#!/usr/local/bin/python2.7
__author__ = 'jriedel'
__description__ = 'Command line utility for quickly managing devices through SSH with some super cool & handy features.'
__version__ = '2.2'

import paramiko
import getpass
import Queue
import threading
import argparse
import os.path
import time
import logging
import re
import datetime
import itertools
import sys
from Crypto.Cipher import AES
from Crypto import Random
import base64
import storePass

# # SETUP AVAILABLE ARGUMENTS ##
parser = argparse.ArgumentParser()
parser.add_argument('-c', action="store", dest="commandString", required=False, help="Command to run")
parser.add_argument('-cf', action="store", dest="commandFile", required=False,
                    help="Specify a 'command file' full of commands to run on selected machine(s)")
parser.add_argument('-ct', action="store", dest="connectTimeout", required=False,
                    help="SSH connect timeout to hosts in seconds: default (10)")
parser.add_argument('-cmdt', action="store", dest="cmdTimeout", required=False, help="Timeout for how long to let commands run: default (60)")
parser.add_argument('-d', action="store", dest="divider", required=False, help="Divide hosts by this number to create chunks of hosts to run at a time.")
parser.add_argument('-e', action="store_true", dest="echoCmd", required=False,
                    help="Echo's the command ran before the result output")
parser.add_argument('--filter', action="store", dest="logFilter", required=False, help="Filter all logs for (i.e. '[RESULT],[SUMMARY]'")
parser.add_argument('-hf', action="store", dest="hostFilePath", required=False,
                    help="Specify your own path to a hosts file")
parser.add_argument('-l', action="store_true", dest="listOnly", required=False, help="List all known hosts")
parser.add_argument('-lf', action="store", dest="logfile", nargs='?', const="nofile", required=False, help="Turns logging on, can also take logfile location as a parameter.")
parser.add_argument('-ll', action="store", dest="logLevel", required=False, help="Set Log Level: DEBUG, INFO (DEFAULT), WARNING, ERROR, CRITICAL")
parser.add_argument('-p', action="store", dest="proxyPort", required=False, help="If using SSH Tunnel, define port to use")
parser.add_argument('-pl', action="store", dest="paramikoLogLevel", required=False, help="Set Paramiko Log Level: DEBUG, INFO, WARNING, ERROR, CRITICAL (DEFAULT)")
parser.add_argument('-r', action="store", dest="hostMatch", required=False,
                    help="Select Hosts matching supplied pattern")
parser.add_argument('-s', action="store_true", dest="sudo", required=False,
                    help="Run command with sudo (performance is much slower)")
parser.add_argument('-t', action="store", dest="threads", required=False, help="Number of threads to run, don't get crazy ! Increasing threads too much can negatively impact performance.")
parser.add_argument('-u', action="store", dest="siteUser", required=False,
                    help="Specify a username (by default I use who you are logged in as)")
parser.add_argument('-1', action="store_true", dest="hostPerPool", required=False, help="One host per pool")
args = parser.parse_args()

############
## GLOBAL ##
############

failed_logins = []
successful_logins = []
home_dir = os.path.expanduser("~")

#############
## LOGGING ##
#############
class ResultFilter(logging.Filter):
    def filter(self, record):
        userFilter = str(args.logFilter)
        if ',' in userFilter:
            filters = userFilter.split(',')
        else:
            filters = [userFilter]
        for filter in filters:
            if filter in record.msg:
                return True

#Paramiko
logging.getLogger('paramiko').setLevel(logging.CRITICAL)
#Runner
logger = logging.getLogger('runner')
if args.logFilter:
    logFilter = ResultFilter()
    logger.addFilter(logFilter)
logging.getLogger('runner').propagate=False
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)
if args.logLevel:
    level = logging.getLevelName(args.logLevel)
    logger.setLevel(level)
if args.paramikoLogLevel:
    level = logging.getLevelName(args.paramikoLogLevel)
    logging.getLogger('paramiko').setLevel(level)

### END OF LOGGING AND GLOBALS ###

def check_args_and_set_default(args):
    ## SET HOSTS FILE ##
    hostFilePath = "%s/.runner/hosts/hosts-all" % (home_dir)

    if args.hostFilePath:
        hostFilePath = args.hostFilePath

    ## SET CONNECT TIMEOUT ##
    connectTimeout = 10
    if args.connectTimeout:
        connectTimeout = int(args.connectTimeout)

    ## SET CMD TIMEOUT ##
    cmdTimeout = None
    if args.cmdTimeout:
        cmdTimeout = args.cmdTimeout

    ## SET THREADS / WORKERS ##
    workers = 10
    if args.threads:
        workers = int(args.threads)

    ## SET USER / PASS ##
    siteUser = getpass.getuser()
    if args.siteUser:
        siteUser = args.siteUser

    ## DEFAULT CHUNKS ##
    # Use -d 0 to turn off chunking
    divider = 10
    if args.divider:
        divider = int(args.divider)

    return (hostFilePath, connectTimeout, cmdTimeout, workers, siteUser, divider)


def create_log(logger):
    ## if they turned logging on, but didn't specify a file, use a default.
    if args.logfile == "nofile":
        logfile_dir = "%s/.runner/logs" % (home_dir)
        tstamp = datetime.datetime.now().strftime("%Y-%m-%d.%H:%M:%S")

        if not os.path.exists(logfile_dir):
            os.makedirs(logfile_dir)
        logfilePath = '%s/runner.log.%s' % (logfile_dir, tstamp)
    else:
        logfile = args.logfile
        logfilePath = os.path.expanduser(logfile)

    fh = logging.FileHandler(logfilePath,"w")
    logger.addHandler(fh)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)

    return logfilePath

def clean_output(output, cmd):
    ## command only
    if re.match(r'^' + cmd + '$', output):
        return False
    # prompt & command
    elif output.startswith('[root') and output.endswith(cmd):
        return False
    # prompt & command different format
    elif output.startswith('root@') and output.endswith('#'):
        return False
    # root prompt only
    elif re.match(r'.*~?]?#$', output):
        return False
    # user prompt only
    elif re.match(r'.*~?]\$$', output):
        return False
    # bash root prompt
    elif re.match(r'^bash.*#$', output):
        return False
    # bash user prompt
    elif re.match(r'^bash.*\$$', output):
        return False
    ## Make sure password is never printed, just in case
    elif re.match(r'' + sitePasswd, output):
        return False

    sudoMsg = ["We trust you have received the usual lecture from the local System",
            "Administrator. It usually boils down to these three things:",
            "#1) Respect the privacy of others.",
            "#2) Think before you type.",
            "#3) With great power comes great responsibility."
            ]

    if any(output in line for line in sudoMsg):
        return False

    return output


def run_cmds(ssh, cmds, hostname, sitePasswd, cmdTimeout):
    ## Echo's commands that provide no results. Helpful when working on network devices (i.e. LTM)
    if args.echoCmd:
        logger.info('[RESULT] - %s: %s' % (hostname, cmd))

    if args.sudo:
        try:
            channel = ssh.invoke_shell()
            channel.settimeout(cmdTimeout)

            buff = ''
            timer=0
            while not buff.endswith('$ '):
                resp = channel.recv(9999)
                buff += resp
                timer += 1
                # This timer fixes a bug where SSH closes immediately after login
                time.sleep(1)
                if timer == connectTimeout:
                    raise Exception("Closing channel because after logging in I didn't receive a prompt after %s seconds" % connectTimeout)

            sudocmd = 'sudo -s'
            channel.send(sudocmd + '\n')
            logger.debug('%s: [SENT] "%s"' % (hostname, sudocmd))

            buff = ''
            while not 'assword' in buff:
                resp = channel.recv(9999)
                buff += resp

            channel.send(sitePasswd + '\n')
            logger.debug('%s: [SENT] sudo pass' % hostname)

            buff = ''
            while not buff.endswith('# '):
                resp = channel.recv(9999)
                buff += resp

            for cmd in cmds:
                ## Echo's commands that provide no results. Helpful when working on network devices (i.e. LTM)
                if args.echoCmd:
                    logger.info('[RESULT] - %s: %s' % (hostname, cmd))
                channel.send(cmd + '\n')
                logger.debug('%s: [SENT] "%s"' % (hostname,cmd))

                buff = ''
                while not buff.endswith('# '):
                    resp = channel.recv(9999)
                    buff += resp

                for line in buff.split('\n'):
                    line = line.strip()
                    if clean_output(line, cmd):
                       logger.info('[RESULT] - %s: %s' % (hostname, line))

        except Exception as e:
            channel.close()
            logger.debug('channel closed')
            raise Exception(e)
        else:
            logger.debug('channel closed')
            channel.close()
    else:
        try:
            for cmd in cmds:
                ## Echo's commands that provide no results. Helpful when working on network devices (i.e. LTM)
                if args.echoCmd:
                    logger.info('[RESULT] - %s: %s' % (hostname, cmd))
                (stdin, stdout, stderr) = ssh.exec_command(cmd, cmdTimeout)
                logger.debug('%s: [SENT] "%s"' % (hostname, cmd))

                for line in stdout.readlines():
                    line = line.rstrip()
                    if clean_output(line, cmd):
                        logger.info('[RESULT] - %s: %s' % (hostname, line))

                ## stderr
                for line in stderr.readlines():
                    line = line.rstrip()
                    logger.info('[RESULT] - %s: %s' % (hostname, line))
        except Exception as e:
            logger.error(e)
            raise Exception(e)
    logger.debug("ssh closed")
    ssh.close()

def ssh_to_host(hosts, sitePasswd, connectTimeout, cmdTimeout):
        for i in range(workers):
            t = threading.Thread(target=worker, args=(siteUser, sitePasswd, connectTimeout, cmdTimeout))
            t.daemon = True
            t.start()

        for hostname in hosts:
            if hostname is not None:
                hostname = hostname.rstrip()
                q.put(hostname)

        q.join()

def worker(siteUser, sitePasswd, connectTimeout, cmdTimeout):
    while True:
        try:
            hostname = q.get()
        except Exception as e:
            logger.exeception(e)
        else:
            node_shell(hostname, siteUser, sitePasswd, connectTimeout, cmdTimeout)
            q.task_done()


def node_shell(hostname, siteUser, sitePasswd, connectTimeout, cmdTimeout):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if not args.proxyPort:
            ssh.connect(hostname, username=siteUser, password=sitePasswd, timeout=connectTimeout, banner_timeout=connectTimeout, look_for_keys=False)
            logger.debug('Connected: %s, %s, %s, proxy disabled' % (hostname, siteUser, connectTimeout))
        else:
            proxyPort = int(args.proxyPort)
            proxyCommandStr = "nc -X 5 -x localhost:%s %s %s" % (proxyPort, hostname, '22')
            proxySock = paramiko.ProxyCommand(proxyCommandStr)
            ssh.connect(hostname, username=siteUser, password=sitePasswd, timeout=connectTimeout, banner_timeout=connectTimeout, sock=proxySock, look_for_keys=False)
            logger.debug('Connected: %s, %s, %s, proxy enabled' % (hostname, siteUser, connectTimeout))
        transport = ssh.get_transport()
        transport.set_keepalive(0)

        if args.commandFile:
            try:
                cmds = open(args.commandFile)
                cmds = [cmd.strip() for cmd in cmds]
            except Exception as e:
                logger.error(e)
        else:
            cmd = args.commandString
            cmds = [cmd]

        run_cmds(ssh, cmds, hostname, sitePasswd, cmdTimeout)

        successful_logins.append(hostname)

    except Exception as e:
        ssh.close()
        logger.debug('ssh closed')
        logger.error('%s: failed to login : %s' % (hostname, e))
        failed_logins.append(hostname)

def get_hosts(hostFilePath):
    ## Expands ~ to users home directory.
    exFilePath = os.path.expanduser(hostFilePath)
    if os.path.exists(exFilePath):
        hosts = open(exFilePath)
        selected_hosts = []
        if not args.hostMatch:
            selected_hosts = list(hosts)
            logger.info('[PARAM SET] - SELECTING ALL HOSTS')
        else:
            hostMatch = args.hostMatch
            for host in hosts:
                if re.search(hostMatch, host):
                    selected_hosts.append(host)
            logger.info('[PARAM SET] - FILTERING ONLY HOSTNAMES MATCHING "%s"' % (hostMatch))
    else:
        logger.error('%s does not exist ! You must create it !' % (hostFilePath))
        exit()

    ## Select one host per pool
    if args.hostPerPool:
        logger.info('[PARAM SET] - 1 HOST PER POOL')
        seen = {}
        hostPerPool = []
        for host in selected_hosts:
            # Here strip values that make hostnames unique like #'s
            # That way the dict matches after 1 host per pool has been seen
            nhost = re.sub("\d+?\.", ".", host)  #Removing #'s in a hostname like host1234.tuxlabs.com, modify this regex for your specific needs
            if not nhost in seen:
                seen[nhost] = 1
                hostPerPool.append(host)
        selected_hosts = hostPerPool

    logger.info('[PARAM SET] - %s HOSTS HAVE BEEN SELECTED' % (len(selected_hosts)))

    return selected_hosts

def list_hosts_and_exit():
    for host in selected_hosts:
        host = host.rstrip()
        print host
    if len(selected_hosts) == 1:
        print "\nThere was %s host listed." % (len(selected_hosts))
    else:
        print "\nThere were %s hosts listed." % (len(selected_hosts))
    exit()

def decrypt_the_pass(encryptedPass):
    try:
        key = storePass.get_key()
        BS = 16
        unpad = lambda s : s[:-ord(s[len(s)-1:])]

        encryptedPass = base64.b64decode(encryptedPass)
        iv = Random.new().read(BS)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decryptedPass = iv + cipher.decrypt(encryptedPass)

        decryptedPass = unpad(decryptedPass[32:])

        return decryptedPass
    except Exception as e:
        logging.error(e)

if __name__ == "__main__":
    (hostFilePath, connectTimeout, cmdTimeout, workers, siteUser, divider) = check_args_and_set_default(args)

    try:
        if args.listOnly or args.commandString or args.commandFile:
            ## if any of these are true, we will need to get the hosts.
            selected_hosts = get_hosts(hostFilePath)
            if args.listOnly:
                list_hosts_and_exit()
            else:
                if len(selected_hosts) == 0:
                    logger.info("No hosts could be found. Ensure you have a hosts file and that your regular expression is matching correctly if you set one.")
                    exit()
                if args.logfile:
                    logfilePath = create_log(logger)
                    logger.info("[PARAM SET] - LOGFILE IS %s" % logfilePath)
                logger.info("[PARAM SET] - USER IS %s" % siteUser)
                logger.info("[PARAM SET] - SSH CONNECT TIMEOUT IS %s SECONDS" % connectTimeout)
                logger.info("[PARAM SET] - THREADS IS %s" % workers)
                if args.sudo:
                    logger.info("[PARAM SET] - SUDO ACTIVATED")
                # Magic that breaks apart your host list chunks of X.
                # if divider is 0, all hosts will be executed.
                if not divider == 0:
                    chunks = list(itertools.izip_longest(*[iter(selected_hosts)]*divider))
                    logger.info("[PARAM SET] - DIVIDER IS %s CREATING %s CHUNKS" % (divider, len(chunks)))
                else:
                    chunks = [selected_hosts]
                    logger.info("[PARAM SET] - TURBO MODE ENABLED - CHUNKING IS DISABLED")

                pfPath = '%s/.runner/.pass' % (home_dir)
                if os.path.isfile(pfPath):
                    try:
                        pf = open(pfPath)
                        encryptedPass = pf.readline()
                        sitePasswd = decrypt_the_pass(encryptedPass)
                        logger.info('[PARAM SET] - RETRIEVED ENCRYPTED PASSWD')
                    except Exception as e:
                        logging.error('%s : Prompting for password instead.' % (e))
                        sitePasswd = getpass.getpass("Please Enter Site Pass: ")
                        print ""
                else:
                    sitePasswd = getpass.getpass("Please Enter Site Pass: ")
                    print ""

                ## start timer ##
                stime = time.time()

                q = Queue.Queue()

                for host_chunk in chunks:
                    ssh_to_host(host_chunk, sitePasswd, connectTimeout, cmdTimeout)

                ## end timer ##
                etime = time.time()
                run_time = int(etime - stime)

                timestamp = str(datetime.timedelta(seconds=run_time))
                print ""
                summary = 'Successfully logged into %s/%s hosts and ran your command(s) in %s second(s)\n' % ((len(successful_logins)), len(selected_hosts), timestamp)
                if len(successful_logins) == 0:
                    summary = 'Failed to login on all %s hosts.' % (len(selected_hosts))
                logger.info('[SUMMARY] - %s' % (summary))
                if len(failed_logins) > 0:
                    for failed_host in failed_logins:
                        logger.info('[FAILED] - to login to: %s' % (failed_host))
                    print ""
                if args.logfile:
                    logger.info("[LOG] - Your logfile can be viewed @ %s" % (logfilePath))
        else:
            parser.print_help()
            print ""
            logger.error("Either -l (list hosts only) or -c (Run command) or -cf (Run command file) is required.")
    except KeyboardInterrupt:
        sys.exit(0)