# Host class
# Copyright (c) 2016, Qualcomm Atheros, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
import subprocess
import threading
import tempfile
import os

logger = logging.getLogger()

def remote_compatible(func):
    func.remote_compatible = True
    return func

def execute_thread(command, reply):
    cmd = ' '.join(command)
    logger.debug("thread run: " + cmd)
    err = tempfile.TemporaryFile()
    try:
        status = 0
        buf = subprocess.check_output(command, stderr=err).decode()
    except subprocess.CalledProcessError as e:
        status = e.returncode
        err.seek(0)
        buf = err.read()
    err.close()

    logger.debug("thread cmd: " + cmd)
    logger.debug("thread exit status: " + str(status))
    logger.debug("thread exit buf: " + str(buf))
    reply.append(status)
    reply.append(buf)

def gen_reaper_file(conf):
    fd, filename = tempfile.mkstemp(dir='/tmp', prefix=conf + '-')
    f = os.fdopen(fd, 'w')

    f.write("#!/bin/sh\n")
    f.write("name=\"$(basename $0)\"\n")
    f.write("echo $$ > /tmp/$name.pid\n")
    f.write("exec \"$@\"\n");

    return filename;

class Host():
    def __init__(self, host=None, ifname=None, port=None, name="", user="root"):
        self.host = host
        self.name = name
        self.user = user
        self.monitors = []
        self.monitor_thread = None
        self.logs = []
        self.ifname = ifname
        self.port = port
        self.dev = None
        self.monitor_params = []
        if self.name == "" and host != None:
            self.name = host

    def local_execute(self, command):
        logger.debug("execute: " + str(command))
        err = tempfile.TemporaryFile()
        try:
            status = 0
            buf = subprocess.check_output(command, stderr=err)
        except subprocess.CalledProcessError as e:
            status = e.returncode
            err.seek(0)
            buf = err.read()
        err.close()

        logger.debug("status: " + str(status))
        logger.debug("buf: " + str(buf))
        return status, buf.decode()

    def execute(self, command):
        if self.host is None:
            return self.local_execute(command)

        cmd = ["ssh", self.user + "@" + self.host, ' '.join(command)]
        _cmd = self.name + " execute: " + ' '.join(cmd)
        logger.debug(_cmd)
        err = tempfile.TemporaryFile()
        try:
            status = 0
            buf = subprocess.check_output(cmd, stderr=err)
        except subprocess.CalledProcessError as e:
            status = e.returncode
            err.seek(0)
            buf = err.read()
        err.close()

        logger.debug(self.name + " status: " + str(status))
        logger.debug(self.name + " buf: " + str(buf))
        return status, buf.decode()

    # async execute
    def execute_run(self, command, res, use_reaper=True):
        if use_reaper:
            filename = gen_reaper_file("reaper")
            self.send_file(filename, filename)
            self.execute(["chmod", "755", filename])
            _command = [filename] + command
        else:
            filename = ""
            _command = command

        if self.host is None:
            cmd = _command
        else:
            cmd = ["ssh", self.user + "@" + self.host, ' '.join(_command)]
        _cmd = self.name + " execute_run: " + ' '.join(cmd)
        logger.debug(_cmd)
        t = threading.Thread(target=execute_thread, name=filename, args=(cmd, res))
        t.start()
        return t

    def execute_stop(self, t):
        if t.name.find("reaper") == -1:
            raise Exception("use_reaper required")

        pid_file = t.name + ".pid"

        if t.isAlive():
            cmd = ["kill `cat " + pid_file + "`"]
            self.execute(cmd)

        # try again
        self.wait_execute_complete(t, 5)
        if t.isAlive():
            cmd = ["kill `cat " + pid_file + "`"]
            self.execute(cmd)

        # try with -9
        self.wait_execute_complete(t, 5)
        if t.isAlive():
            cmd = ["kill -9 `cat " + pid_file + "`"]
            self.execute(cmd)

        self.wait_execute_complete(t, 5)
        if t.isAlive():
            raise Exception("thread still alive")

        self.execute(["rm", pid_file])
        self.execute(["rm", t.name])

    def wait_execute_complete(self, t, wait=None):
        if wait == None:
            wait_str = "infinite"
        else:
            wait_str = str(wait) + "s"

        logger.debug(self.name + " wait_execute_complete(" + wait_str + "): ")
        if t.isAlive():
            t.join(wait)

    def add_log(self, log_file):
        self.logs.append(log_file)

    def get_logs(self, local_log_dir=None):
        for log in self.logs:
            if local_log_dir:
                self.local_execute(["scp", self.user + "@[" + self.host + "]:" + log, local_log_dir])
            self.execute(["rm", log])
        del self.logs[:]

    def send_file(self, src, dst):
        if self.host is None:
            return
        self.local_execute(["scp", src,
                            self.user + "@[" + self.host + "]:" + dst])
