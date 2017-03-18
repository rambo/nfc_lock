#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
import os, sys
from exceptions import NotImplementedError,RuntimeError,KeyboardInterrupt
import sqlite3
# Decimal recipe from http://stackoverflow.com/questions/6319409/how-to-convert-python-decimal-to-sqlite-numeric
#import decimal
# Register the adapter
#sqlite3.register_adapter(decimal.Decimal, lambda d: str(d))
# Register the converter
#sqlite3.register_converter("NUMERIC", lambda s: decimal.Decimal(s))
# Register converter&adapter for datetime in the same way
import datetime
sqlite3.register_adapter(datetime.datetime, lambda dt: dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:23])
# The type on SQLite is "TIMESTAMP" even if we specified "DATETIME" in table creation...
sqlite3.register_converter("TIMESTAMP", lambda s: datetime.datetime.strptime(s.ljust(26,"0"), "%Y-%m-%d %H:%M:%S.%f"))

import yaml
import zmq
from zmq.eventloop.zmqstream import ZMQStream


class keyserver(object):
    config_file = None
    mainloop = None
    sqlite_connection = None
    sqlite_cursor = None
    db_file =  None

    def __init__(self, config_file, mainloop):
        self.config_file = config_file
        self.mainloop = mainloop
        self.reload()

    def hook_signals(self):
        """Hooks POSIX signals to correct callbacks, call only from the main thread!"""
        import signal as posixsignal
        posixsignal.signal(posixsignal.SIGTERM, self.quit)
        posixsignal.signal(posixsignal.SIGQUIT, self.quit)
        posixsignal.signal(posixsignal.SIGHUP, self.reload)

    def reload(self, *args):
        if self.sqlite_connection:
            self.sqlite_connection.close()
        with open(self.config_file) as f:
            self.config = yaml.load(f)
        if os.path.exists(self.config['keydb']):
            self.db_file = os.path.realpath(self.config['keydb'])
        else:
            self.db_file = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(self.config_file)), self.config['keydb']))
        if not os.path.exists(self.db_file):
            raise RuntimeError("DB file %s does not exist!" % self.db_file)
        self.sqlite_connection = sqlite3.connect(self.db_file, detect_types=sqlite3.PARSE_DECLTYPES)
        self.sqlite_cursor = self.sqlite_connection.cursor()
        
        self.zmq_context = zmq.Context()
        self.zmq_socket = self.zmq_context.socket(zmq.REP)
        self.zmq_socket.bind(self.config['rep_socket'])
        self.zmq_stream = ZMQStream(self.zmq_socket)
        self.zmq_stream.on_recv(self._on_recv)

        print("Config (re-)loaded")

    def _on_recv(self, data, *args, **kwargs):
        #print("_on_recv: data=%s" % repr(data))
        if len(data) != 1:
            self.zmq_stream.send_multipart(["INV", "0x0"]) # Invalid request
            return

        uid = data[0].lower()

        self.sqlite_cursor.execute("SELECT rowid FROM revoked_tokens WHERE value=?;", (uid, ) )
        revokeddata = self.sqlite_cursor.fetchone()
        if revokeddata:
            # PONDER: Do we log this here or let the gatekeeper program to publish the final result ?
            self.zmq_stream.send_multipart(["REV", "0x0"]) # Revoked card
            return

        self.sqlite_cursor.execute("SELECT acl FROM valid_tokens WHERE value=?;", (uid, ) )
        acldata = self.sqlite_cursor.fetchone()
        if not acldata:
            # PONDER: Do we log this here or let the gatekeeper program to publish the final result ?
            self.zmq_stream.send_multipart(["NF", "0x0"]) # Not found
            return

        # PONDER: About logging: note that we do not yet know if this ACL is accepted at the gatekeeper end
        self.zmq_stream.send_multipart(["OK", "0x%x" % acldata[0]])
        

    def quit(self, *args):
        # This will close the sockets too
        self.zmq_context.destroy()
        self.mainloop.stop()

    def run(self):
        print("Starting mainloop")
        self.mainloop.start()



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: keyserver.py config.yml")
        sys.exit(1)

    # TODO: Use tornado from ZMQ
    from zmq.eventloop import ioloop
    ioloop.install()
    loop = ioloop.IOLoop.instance()
    instance = keyserver(sys.argv[1], loop)
    instance.hook_signals()
    try:
        instance.run()
    except KeyboardInterrupt:
        instance.quit()
