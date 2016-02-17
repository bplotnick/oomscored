#!/usr/bin/env python
import os, sys, signal, atexit
import errno
import socket
import select
import logging
import string
import re
import pwd,grp
import fnmatch
from collections import defaultdict

import proc_events as pec
from proc_events import netlink
from proc_events import connector

TARGET_EVENTS = ["PROC_EVENT_FORK",
                 "PROC_EVENT_EXEC",
                 "PROC_EVENT_UID",
                 "PROC_EVENT_GID",
                 ]

DEFAULT_PATTERN=re.compile(r'.*')
class MissingProcFileException(Exception):
    pass

'''
pid_to_procname tries its hardest to get the the fullpath of the process from the pid
Generally speaking it tries the following places in order:
1. /proc/<pid>/status
2. /proc/<pid>/exe (readlink)
3. /proc/<pid>/cmdline
Algorithm borrowed from cgrulesengd from libcgroup
'''
def pid_to_procname(pid):
    try:
        with open("/proc/%s/status"%pid,'r') as f:
            firstline = f.readline()
    except IOError:
        logging.debug("pid: %s no status file"%pid)
        raise MissingProcFileException("Status file; pid %s"%pid)
    
    assert(firstline.startswith("Name:"))
    pname_status = firstline.split('\t')[1].strip()
    logging.debug("pid: %d, pname_status %s"%(pid,pname_status))
    try:
        procname = os.readlink("/proc/%s/exe"%pid)
    except OSError:
        # This is a kernel thread, use the procname from status
        return pname_status
    logging.debug("pid: %d, procname %s"%(pid,procname))

    # procname from status is limited to 15 chars
    if pname_status == os.path.basename(procname)[:16]:
        return procname

    # This is usually the case of a shell script
    # We compare the script name with status and then get the fullpath
    try:
        with open("/proc/%s/cmdline"%pid) as f:
            l = f.readline()
            pname_cmdline = l[len(procname):].strip()
            # I'm not sure why, but /proc/<pid>/cmdline is returning a null-terminated string, which we need to get rid of
            pname_cmdline = filter(lambda x: x in string.printable, pname_cmdline)
    except IOError:
        logging.debug("pid: %s no cmdline file"%pid)
        raise MissingProcFileException("cmdline file; pid %s"%pid)

    logging.debug("pid: %d, pname_cmdline %s"%(pid,pname_cmdline))
    
    if pname_status == os.path.basename(pname_cmdline)[:16]:
        cwd = os.readlink("/proc/%s/cwd"%pid)
        # to get full path we prepend cwd and then call realpath to simplify (usually dots in the path)
        return os.path.realpath(os.path.sep.join([cwd,pname_cmdline]))

    # If we get here, we're likely executing a symbolic link... return /proc/<pid>/exe
    return procname

def get_pid_from_evt(evt):
    if evt["what"] == "PROC_EVENT_FORK":
        pid = evt["child_pid"]
    else:
        pid = evt["process_pid"]
    return pid

'''
get_ids takes in an event and extracts the effective uid and effective gid
In the case of EVENT_UID or EVENT_GID, it will use the euid/egid from the event
'''
def get_ids(evt):
    pid = get_pid_from_evt(evt)
    procstatus = {}
    try:
        with open("/proc/%s/status"%pid,'r') as f:
            for l in f.readlines():
                try:
                    k,v = l.split(":",1)
                except Exception as e:
                    raise e
                procstatus[k] = v.strip()
    except IOError:
        logging.debug("pid: %s no status file"%pid)
        raise MissingProcFileException("Status file; pid %s"%pid)

    euid = procstatus["Uid"].split()[1]
    egid = procstatus["Gid"].split()[1]
            
    if evt["what"] == "PROC_EVENT_UID":
        euid = evt["euid"]
    elif evt["what"] == "PROC_EVENT_GID":
        egid = evt["egid"]    
    return (int(euid),int(egid))

'''
attempts to change the oom_score_adj 
'''
def change_oom_score(pid,score):
    try:
        with open("/proc/%s/oom_score_adj"%pid,"rw+") as f:
            oldscore=f.readline().strip()
            logging.info("changing oom score for pid: %s [old: %s, new: %s]"%(pid,oldscore,str(score)))
            f.write(str(score))
    except IOError:
        logging.debug("pid: %s no oom_score_adj file"%pid)
        raise MissingProcFileException("oom_score_adj file; pid %s"%pid)

'''
transform_event takes a proc_event and transforms the pids into what we in userland are used to
the transformation is a simple swap of tgid and pid
    from linux/cn_proc.h
 32 /*
 33  * From the user's point of view, the process
 34  * ID is the thread group ID and thread ID is the internal
 35  * kernel "pid". So, fields are assigned as follow:
 36  *
 37  *  In user space     -  In  kernel space
 38  *
 39  * parent process ID  =  parent->tgid
 40  * parent thread  ID  =  parent->pid
 41  * child  process ID  =  child->tgid
 42  * child  thread  ID  =  child->pid
 43  */
'''
def transform_event(event):
    new_event = event.copy()

    if "parent_pid" in event:
        new_event["parent_pid"] = event["parent_tgid"]
        new_event["parent_tgid"] = event["parent_pid"]

    if "child_pid" in event:
        new_event["child_pid"] = event["child_tgid"]
        new_event["child_tgid"] = event["child_pid"]

    if "process_pid" in event:
        new_event["process_pid"] = event["process_tgid"]
        new_event["process_tgid"] = event["process_pid"]

    ### We don't handle tracer events currently
    # if "tracer_pid" in event:
    #     new_event["tracer_pid"] = event["tracer_tgid"]
    #     new_event["tracer_tgid"] = event["tracer_pid"]

    return new_event
    
class EventListener(object):
    def __init__(self,pidfile="/var/run/oomscored.pid",cfgfilename="/etc/oomrules.conf"):

        self.stdin = "/dev/null"
        self.stdout = "/dev/null"
        self.stderr = "/dev/null"
        self.pidfile = pidfile

        self.cfgfilename = cfgfilename
        self.sockfd = socket.socket(socket.AF_NETLINK,
                          socket.SOCK_DGRAM,
                          netlink.NETLINK_CONNECTOR)

        self.rule_map_by_uid = defaultdict(dict)
        self.rule_map_by_gid = defaultdict(dict)

        self.reload_rules=False
        signal.signal(signal.SIGUSR1,self.handle_sigusr1)
        #  Netlink sockets are connected with pid and message group mask,
        #  message groups are for multicast protocols (like our process event
        #  connector).

        try:
            self.sockfd.bind((os.getpid(), connector.CN_IDX_PROC))
        except socket.error as (_errno, errmsg):
            if _errno == errno.EPERM:
                print ("You don't have permission to bind to the "
                       "process event connector. Try sudo.")
                raise SystemExit(1)
            raise
            
    def handle_sigusr1(self,signum,frame):
        logging.info("Caught signal %d"%signum)
        assert(signum==signal.SIGUSR1)
        self.reload_rules = True
        
        
    def parse_rule_config(self):
        #NOTE: If we decide to allow arbitrary rules to be added ad-hoc (we currently don't), we'll need to store the ad-hoc rules when reloading
        filename = self.cfgfilename

        logging.debug("parsing config file %s"%filename)

        self.rule_map_by_uid = defaultdict(dict)
        self.rule_map_by_gid = defaultdict(dict)

        with open(filename,'r') as f:
            cfg = f.readlines()

        commentre = re.compile(r'^#.*$')
        cfgre = re.compile(r'^(?P<user>\S+)\s+(?P<pattern>\S+)\s+(?P<oom_score_adj>\-?[0-9]+)\s*(#.*)?$')
        
        #TODO: Sanitize input
        for l in cfg:
            if commentre.match(l): # Comment line
                continue
            m = cfgre.match(l) # incorrectly formatted line. do we want to error here??
            if not m:
                continue
            d = m.groupdict()

            if (int(d['oom_score_adj']) > 1000) or (int(d['oom_score_adj']) < -1000):
                logging.warning("oom_score_adj must be in the range [-1000,1000], ignoring rule:\n%s"%l)
                continue
                
            # Do we want to accept uids/gids?
            if d['user'].startswith("@"): # It's a group
                # lookup gid from group (hopefully the gid doesn't change!)
                try:
                    gid = grp.getgrnam(d['user'][1:]).gr_gid
                except KeyError as e:
                    logging.warning("invalid group %s! ignoring rule: \n%s"%(d['user'],l))
                    continue
                self.register_rule(gid=gid,procpattern=fnmatch.translate(d['pattern']),score_adj=int(d['oom_score_adj']))
            else: # It's a user or wildcard
                if d['user'] != "*":
                    # lookup uid from username (hopefully the uid doesn't change!)
                    try:
                        uid = pwd.getpwnam(d['user']).pw_uid
                    except KeyError as e:
                        logging.warning("invalid user %s! ignoring rule: \n%s"%(d['user'],l))
                        continue
                else:
                    uid = d['user']
                self.register_rule(uid=uid,procpattern=fnmatch.translate(d['pattern']),score_adj=int(d['oom_score_adj']))
    

    def process_one_event(self,evt):
        #1. lookup processname from pid
        pid = get_pid_from_evt(evt)
        procname = pid_to_procname(pid)

        #2. get euid and/or egid depending on what event we are
        euid,egid = get_ids(evt)
        logging.debug("event procname: %s, pid: %d, euid: %d, egid: %d"%(procname,pid,euid,egid))

        #3. try to match in rules
        oomscoreadj = self.get_oom_rule_match(euid,egid,procname)

        #4. apply oom score (if rule matched)
        if oomscoreadj:
            change_oom_score(pid,oomscoreadj)
            logging.info("changed oomscore for %s to %d, pid: %d, euid: %d, egid: %d"%(procname,oomscoreadj,pid,euid,egid))
                
        

    def get_oom_rule_match(self,euid,egid,procpathname):
        procname = os.path.basename(procpathname)
        #1. match (uid,process)
        x = self.rule_map_by_uid.get(euid)
        if x:
            for (pattern,oomscore) in x.iteritems():
                if (pattern != DEFAULT_PATTERN) and (pattern.match(procname)):
                    logging.debug("process matched 1 (uid,process): euid: %d, procname: %s, oomscore: %s"%(euid,procname,oomscore))
                    return oomscore

        #2. match (gid,process)
        x = self.rule_map_by_gid.get(egid)
        if x:
            for (pattern,oomscore) in x.iteritems():
                if (pattern != DEFAULT_PATTERN) and (pattern.match(procname)):
                    logging.debug("process matched 2 (gid,process): egid: %d, procname: %s, oomscore: %s"%(egid,procname,oomscore))
                    return oomscore

        #3. match (uid,*)
        x = self.rule_map_by_uid.get(euid)
        if x:
            oomscore = x.get(DEFAULT_PATTERN)
            if oomscore: # We end up not needing to match DEFAULT_PATTERN since we know it matches everything
                logging.debug("process matched 3 (uid,*): euid: %d, procname: %s, oomscore: %s"%(euid,procname,oomscore))
                return oomscore


        #4. match (gid,*)
        x = self.rule_map_by_gid.get(egid)
        if x:
            oomscore = x.get(DEFAULT_PATTERN)
            if oomscore:
                logging.debug("process matched 4 (gid,*): egid: %d, procname: %s, oomscore: %s"%(egid,procname,oomscore))
                return oomscore

        #5. match (*,process)
        x = self.rule_map_by_uid.get("*")
        if x:
            for (pattern,oomscore) in x.iteritems():
                if (pattern != DEFAULT_PATTERN) and (pattern.match(procname)):
                    logging.debug("process matched 5 (*,process): procname: %s, oomscore: %s"%(procname,oomscore))
                    return oomscore
                
        #6. match (*,*)
        x = self.rule_map_by_uid.get("*")
        if x:
            oomscore = x.get(DEFAULT_PATTERN)
            if oomscore:
                logging.debug("process matched 6 (*,*): procname: %s, oomscore: %s"%(procname,oomscore))
                return oomscore

        logging.debug("no rules matched: euid: %d, egid: %d, procname: %s"%(euid,egid,procname))
        return None
        
    def event_loop(self):
        pec.control(self.sockfd, listen=True)
        while True:
            # If we catch a signal while in select, we will get an InterruptedSystemCall exception (EINTR)
            # I don't think this is a problem, so we'll just catch it and move on
            try:
                (readable, w, e) = select.select([self.sockfd],[],[])
            except select.error as e:
                if e[0] != errno.EINTR:
                    raise
                else:
                    pass

            buf = readable[0].recv(256)
            event = pec.unpack(buf)
            event["what"] = pec.process_events_rev.get(event.what)

            # Transform event into one that actually makes sense to us in userland
            new_event = transform_event(event)

            if self.reload_rules:
                # We got signaled for rule reload
                self.reload_rules = False
                self.parse_rule_config()

            if new_event["what"] in TARGET_EVENTS:
                logging.debug(new_event)
                # We don't differentiate between FORK events from clone or from fork (threads or processes)
                # oom_score can (and should) be adjusted on a per pid basis
                try:
                    self.process_one_event(new_event)
                except MissingProcFileException as e:
                    continue


    def register_rule(self,uid=None,gid=None,procpattern=r".*",score_adj=0):
        # is uid or gid?
        if (uid == None) and (gid == None):
            raise Exception("Specify uid OR gid, but not both")
        if (gid != None):
            logging.info("Registering rule (gid: %s, pattern: %s, score: %d)"%(str(gid),procpattern,score_adj))
            self.rule_map_by_gid[gid][re.compile(procpattern)]=score_adj
        else:
            if (uid==None):
                uid="*"
            logging.info("Registering rule (uid: %s, pattern: %s, score: %d)"%(str(uid),procpattern,score_adj))
            self.rule_map_by_uid[uid][re.compile(procpattern)]=score_adj

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
      
        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
      
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
      
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    def delpid(self):
        os.remove(self.pidfile)

    def write_pidfile(self):
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)
       

    def close(self):
        logging.info("shutting down")
        pec.control(self.sockfd, listen=False)
        self.sockfd.close()


if __name__ == "__main__":
    #FIXME: Usage, daemonize, richer logging (syslog?), documentation, code coverage
    #FIXME: Should we try to make these operations reversable? i.e. store the oom scores before we start?
    logfilename = "/tmp/oomrules.log"
    daemonize = False #FIXME
    filename = logfilename if daemonize else None
    FORMAT='%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
    logging.basicConfig(filename=filename,format=FORMAT,level=logging.INFO)

    e = EventListener(cfgfilename="/etc/oomrules.conf")
    e.parse_rule_config()
    if daemonize:
       e.daemonize()

    #e.write_pidfile()
    e.event_loop()
    e.close()

