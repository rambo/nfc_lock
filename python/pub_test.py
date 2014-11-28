#!/usr/bin/env python
import os, sys
import yaml
import zmq
from zmq.eventloop import ioloop
from zmq.eventloop.zmqstream import ZMQStream
import itertools
import random


if len(sys.argv) < 2:
    print("Usage: sub_test.py config.yml")
    sys.exit(1)

with open(sys.argv[1]) as f:
    config = yaml.load(f)

ioloop.install()

context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.bind(config['gatekeeper_socket'].replace('tcp://localhost:', 'tcp://*:'))
stream = ZMQStream(socket)


topic = itertools.cycle(('tagresult','foo','bar'))

def send_random_data():
    data = "%s bottles of beer on the wall" % random.randint(0,100000)
    #socket.send_multipart((topic.next(), data))
    stream.send_multipart((topic.next(), data))

pcb = ioloop.PeriodicCallback(send_random_data, 500)
pcb.start()

print("Starting IOLoop")
ioloop.IOLoop.instance().start()
