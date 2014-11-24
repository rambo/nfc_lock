#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
import os, sys
import yaml
import zmq


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: req_test.py config.yml")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        config = yaml.load(f)

    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(config['rep_socket'].replace('tcp://*:','tcp://127.0.0.1:'))
    
    print("Sending request")
    socket.send("Hello")
    print("Waiting for reply")
    message = socket.recv()
    print("Got reply: %s" % repr(message))
    

    