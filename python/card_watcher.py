#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,os

import datetime
import yaml
import couchdb
import zmq
from zmq.eventloop.zmqstream import ZMQStream

# Reminder:  RPi.GPIO uses /dev/mem and requires root access, so that will not solve our GPIO issue
import usergpio

#usergpio.FAKE = True

class card_watcher(object):
    mainloop = None
    config_file = None
    config = {}
    zmq_context = None
    relay_disable_timer = None
    fobblogdb = None
    led_timer = None
    heartbeat_timer = None
    heartbeat_counter = 0
    relay_pin = None
    leds = None
    
    def __init__(self, config_file, mainloop):
        self.config_file = config_file
        self.mainloop = mainloop
        self.reload()
        print("Initialized")

    def leds_off(self, *args):
        # We get event info from the (possible) timer, that's why we need to accept more arguments even if we do not care about them
        self.leds.set_all_rgb(0,0,0)
        self.led_timer = None
        # To disable the timer that called this
        if self.led_timer:
            self.mainloop.remove_timeout(self.led_timer)
            self.led_timer = None
        return False

    def disable_relay(self, *args):
        # We get event info from the (possible) timer, that's why we need to accept more arguments even if we do not care about them
        self.relay.set(True)
        self.relay_disable_timer = None
        # To disable the timer that called this
        return False

    def hook_signals(self):
        """Hooks POSIX signals to correct callbacks, call only from the main thread!"""
        import signal as posixsignal
        posixsignal.signal(posixsignal.SIGTERM, self.quit)
        posixsignal.signal(posixsignal.SIGQUIT, self.quit)
        posixsignal.signal(posixsignal.SIGHUP, self.reload)

    def log(self, card_uid, card_valid):
        if not self.fobblogdb:
            self.reconnect_couchdb()
            if not self.fobblogdb:
                return False

        try:
            return self.fobblogdb.save({
                "card_uid": card_uid,
                "card_valid": card_valid,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "action": self.config['log']['action'],
            })
        except Exception as e:
            # TODO: catch couchdb/socket errors only
            print("log: got e=%s" % repr(e))
            return False

    def reconnect_couchdb(self):
        self.fobblogdb = None
        try:
            couch = couchdb.Server(self.config['log']['server'])
            self.fobblogdb = couch[self.config['log']['db']]
        except Exception as e:
            # TODO: catch socket errors only
            print("reconnect_couchdb: got e=%s" % repr(e))

    def reload(self, *args):
        with open(self.config_file) as f:
            self.config = yaml.load(f, Loader=yaml.SafeLoader)

        self.reconnect_couchdb()

        # Init relay GPIO
        self.relay = usergpio.gpiopin(4, dir="out")
        self.relay.set(True)

        # Turn the LEDs off (and init the gpio for them)
        self.leds = usergpio.ledstring(data_pin=self.config['leds']['datapin'],
                                       clk_pin=self.config['leds']['clkpin'],
                                       n=self.config['leds']['n'])
        self.leds.set_all_rgb(10,10,10)
        self.led_timer = self.mainloop.call_later(self.config['leds']['error']['time'], self.leds_off)

        if self.zmq_context:
            self.zmq_context.destroy()
            self.zmq_context = None
        self.zmq_context = zmq.Context()
        self.zmq_socket = self.zmq_context.socket(zmq.SUB)
        self.zmq_socket.connect(self.config['gatekeeper_socket'])
        #subscribe all topics
        self.zmq_socket.setsockopt(zmq.SUBSCRIBE, b'')
        self.zmq_stream = ZMQStream(self.zmq_socket)
        self.zmq_stream.on_recv(self._on_recv)

        self.start_heartbeat()
        print("Config (re-)loaded")

    def _on_recv(self, packet):
        topic = packet[0].decode('ascii')
        data = packet[1:]

        print("_on_recv topic=%s, data=%s" % (topic, repr(data)))

        if topic == "OK":
            self.valid_card_seen(data[0].decode('ascii'))
            return

        # Other results are failures
        print("Card %s not valid (reason: %s)" % (data[0], topic))
        self.leds.set_all_rgb(255,0,0)
        self.led_timer = self.mainloop.call_later(self.config['leds']['error']['time'], self.leds_off)

        self.log(data[0].decode('ascii'), topic)

    def valid_card_seen(self, card_uid):
        print("Card %s valid, activating relay for %d seconds" % (card_uid, self.config['relay']['time']))
        if self.relay_disable_timer:
            self.mainloop.remove_timeout(relay_disable_timer)
        self.relay.set(False)
        self.mainloop.call_later(self.config['relay']['time'], self.disable_relay)

        #LED indication
        self.leds.set_all_rgb(0,255,0)
        self.led_timer = self.mainloop.call_later(self.config['leds']['ok']['time'], self.leds_off)

        self.log(card_uid, "OK")

    def _get_heartbeat_time(self):
        k = self.heartbeat_counter % len(self.config['leds']['heartbeat']['time'])
        return (self.config['leds']['heartbeat']['time'][k])

    def start_heartbeat(self):
        self.heartbeat_counter = 0
        self.leds.setstr("w")
        self.heartbeat_timer = self.mainloop.call_later(1, self.heartbeat_callback)

    def heartbeat_callback(self, *args):
        self.heartbeat_counter += 1

        #If LEDs are not reserved, blink HB
        if not self.led_timer:
            if (self.heartbeat_counter % 2):
                #odd numbers mean it's turn-off time
                self.leds.setstr("w......")
            else:
                self.leds.setstr(".......")
                
        self.heartbeat_timer = self.mainloop.call_later(self._get_heartbeat_time(), self.heartbeat_callback)
        # TODO: we should probably zero out the hearbeat counter every once in a while
        if self.heartbeat_counter >= len(self.config['leds']['heartbeat']['time']):
            self.heartbeat_counter = 0

    def quit(self, *args):
        # This will close the sockets too
        if self.zmq_context:
            self.zmq_context.destroy()
        self.mainloop.stop()

    def run(self):
        print("Starting mainloop")
        self.mainloop.start()



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: card_watcher.py config.yml")
        sys.exit(1)
    #TODO: init GPIO and do seteuid() to non-root account after that
    from tornado import ioloop
    loop = ioloop.IOLoop.instance()
    instance = card_watcher(sys.argv[1], loop)
    instance.hook_signals()
    try:
        instance.run()
    except KeyboardInterrupt:
        instance.quit()
