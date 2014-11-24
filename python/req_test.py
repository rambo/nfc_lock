#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
import os, sys
import yaml
import zmq
import time
from zmq.eventloop.zmqstream import ZMQStream


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: req_test.py config.yml card_uid")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        config = yaml.load(f)

    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(config['rep_socket'].replace('tcp://*:','tcp://127.0.0.1:'))
    
    while(True):
        print("Sending request")
        socket.send(sys.argv[2])
        print("Waiting for reply")
        message = socket.recv_multipart()
        print("Got reply: %s" % repr(message))
        time.sleep(1)

