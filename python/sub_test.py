#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
import os, sys
import yaml
import zmq
import time
from zmq.eventloop.zmqstream import ZMQStream
from zmq.eventloop import ioloop

def stream_recv_callback(*args):
    print(repr(args))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: sub_test.py config.yml")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        config = yaml.load(f)

    ioloop.install()
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect(config['gatekeeper_socket'])
    socket.setsockopt(zmq.SUBSCRIBE, 'tagresult')

    stream = ZMQStream(socket)
    stream.on_recv(stream_recv_callback)
    print("Starting IOLoop")
    ioloop.IOLoop.instance().start()

