#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
import sys,os
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

## db init example
# sqlite3 keys.db
# CREATE TABLE valid_keys (card_uid TEXT NOT NULL, secure_uid TEXT NOT NULL);
# INSERT INTO valid_keys (card_uid, secure_uid) VALUES ("YOUR_UID_HERE", "NA");

import dbus
import gobject
import yaml
import couchdb

# Reminder:  RPi.GPIO uses /dev/mem and requires root access, so that will not solve our GPIO issue
import usergpio


class card_watcher(object):
    mainloop = None
    db_file = None
    config_file = None
    config = {}
    bus = None
    connection = None
    cursor = None
    relay_disable_timer = None
    fobblogdb = None
    error_led_timer = None
    ok_led_timer = None
    heart_led_timer = None
    heartbeat_counter = 0
    

    def __init__(self, config_file, mainloop, bus):
        self.config_file = config_file
        self.mainloop = mainloop
        self.bus = bus
        self.reload()
        self.bus.add_signal_receiver(handler_function=self.card_seen, dbus_interface="org.nfc_tools.nfcd.NfcDevice", signal_name="targetAdded")
        print("Initialized")

    def disable_ok_led(self, *args):
        # We get event info from the (possible) timer, that's why we need to accept more arguments even if we do not care about them
        usergpio.set_value(self.config['leds']['ok']['pin'], 0)
        self.ok_led_timer = None
        # To disable the timer that called this
        return False

    def disable_error_led(self, *args):
        # We get event info from the (possible) timer, that's why we need to accept more arguments even if we do not care about them
        usergpio.set_value(self.config['leds']['error']['pin'], 0)
        self.error_led_timer = None
        # To disable the timer that called this
        return False

    def disable_relay(self, *args):
        # We get event info from the (possible) timer, that's why we need to accept more arguments even if we do not care about them
        self.set_relay_state(False)
        self.relay_disable_timer = None
        # To disable the timer that called this
        return False

    def set_relay_state(self, state):
        #print("calling usergpio.set_value(%s, %s)" % (self.config['relay']['pin'], int(state)))
        usergpio.set_value(self.config['relay']['pin'], int(state))

    def card_seen(self, *args):
        card_uid = str(args[0])
        #print("Got card %s" % card_uid)
        if self.card_valid(card_uid):
            print("Card %s valid, activating relay for %d seconds" % (card_uid, self.config['relay']['time']))
            if self.relay_disable_timer:
                gobject.source_remove(self.relay_disable_timer)
            self.set_relay_state(True)
            self.relay_disable_timer = gobject.timeout_add(int(self.config['relay']['time']*1000), self.disable_relay)
            
            usergpio.set_value(self.config['leds']['ok']['pin'], 1)
            self.ok_led_timer = gobject.timeout_add(int(self.config['leds']['ok']['time']*1000), self.disable_ok_led)

            self.log(card_uid, True)
        else:
            print("Card %s not valid" % card_uid)

            usergpio.set_value(self.config['leds']['error']['pin'], 1)
            self.error_led_timer = gobject.timeout_add(int(self.config['leds']['error']['time']*1000), self.disable_error_led)

            self.log(card_uid, False)

    def card_valid(self, card_uid):
        self.cursor.execute("SELECT card_uid,secure_uid FROM valid_keys WHERE card_uid=?;", (card_uid.lower(), ) )
        data = self.cursor.fetchone()
        if not data:
            return False
        # TODO: Query the card for the secure_uid and verify it (probably not doable via the D-Bus interface, btw)
        return True

    def hook_signals(self):
        """Hooks POSIX signals to correct callbacks, call only from the main thread!"""
        import signal as posixsignal
        posixsignal.signal(posixsignal.SIGTERM, self.quit)
        posixsignal.signal(posixsignal.SIGQUIT, self.quit)
        posixsignal.signal(posixsignal.SIGHUP, self.reload)

    def log(self, card_uid, card_valid):
        self.fobblogdb.save({
            "card_uid": card_uid,
            "card_valid": card_valid,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "action": self.config['log']['action'],
        })

    def reload(self, *args):
        if self.connection:
            self.connection.close()
        with open(self.config_file) as f:
            self.config = yaml.load(f)
        self.db_file = self.config['keydb']
        self.connection = sqlite3.connect(self.db_file, detect_types=sqlite3.PARSE_DECLTYPES)
        self.cursor = self.connection.cursor()

        couch = couchdb.Server(self.config['log']['server'])
        self.fobblogdb = couch[self.config['log']['db']]

        # Init relay GPIO
        self.set_relay_state(False)
        
        # Turn the LEDs off (and init the gpio for them)
        for k in self.config['leds']:
            usergpio.set_value(self.config['leds'][k]['pin'], 0)
        
        self.start_heartbeat()
        print("Config (re-)loaded")
        

    def _get_heartbeat_ms(self):
        k = self.heartbeat_counter % len(self.config['leds']['heartbeat']['time'])
        return int(self.config['leds']['heartbeat']['time'][k] * 1000)

    def start_heartbeat(self):
        self.heartbeat_counter = 0
        usergpio.set_value(self.config['leds']['heartbeat']['pin'], 1)
        self.heart_led_timer = gobject.timeout_add(self._get_heartbeat_ms(), self.heartbeat_callback)

    def heartbeat_callback(self, *args):
        self.heartbeat_counter += 1
        if (self.heartbeat_counter % 2):
            # odd numbers mean it's turn-off time
            usergpio.set_value(self.config['leds']['heartbeat']['pin'], 0)
        else:
            usergpio.set_value(self.config['leds']['heartbeat']['pin'], 1)
        self.heart_led_timer = gobject.timeout_add(self._get_heartbeat_ms(), self.heartbeat_callback)
        # TODO: we should probably zero out the hearbeat counter every once in a while
        if self.heartbeat_counter >= len(self.config['leds']['heartbeat']['time']):
            self.heartbeat_counter = 0

    def quit(self, *args):
        self.mainloop.quit()

    def run(self):
        print("Starting mainloop")
        self.mainloop.run()



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: card_watcher.py config.yml")
        sys.exit(1)

    from dbus.mainloop.glib import DBusGMainLoop
    DBusGMainLoop(set_as_default=True)
    system_bus = dbus.SystemBus()
    loop = gobject.MainLoop()
    
    instance = card_watcher(sys.argv[1], loop, system_bus)
    instance.hook_signals()
    try:
        instance.run()
    except KeyboardInterrupt:
        instance.quit()
