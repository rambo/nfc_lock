#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Very quick and dirty module to do basic GPIO stuff on /sys/class/gpio/ (to which normal users can be given access with relative safety, 
/dev/mem, which RPi.GPIO uses is definitely root-only -land)"""
import os

def channel_controlpath(channel):
    """Get the /sys/class/gpio/ -path for the given channel"""
    return "/sys/class/gpio/gpio%d" % int(channel)

def conditional_export(channel):
    """Call export if channel is not exported"""
    if os.path.isdir(channel_controlpath(channel)):
        return True
    return export(channel)

def export(channel):
    """Exports the given channel to /sys/class/gpio/"""
    with open("/sys/class/gpio/export", 'w') as f:
        f.write(str(channel))
    return True

def set_direction(channel, direction):
    """Set direction ('in' or 'out') of the channel"""
    conditional_export(channel)
    path = "%s/direction" % channel_controlpath(channel)
    with open(path, 'w') as f:
        f.write(direction)
    return True

def set_value(channel, value):
    """Set value for the channel (forces it to 'out' direction first)"""
    set_direction(channel, 'out')
    path = "%s/value" % channel_controlpath(channel)
    #print("path=%s value=%s" % (path, value))
    with open(path, 'w') as f:
        f.write(str(value))
    return True

def red_value(channel):
    """UNTESTED: Reads the value from given channel (forces it to 'in' direction first)"""
    set_direction(channel, 'in')
    path = "%s/value" % channel_controlpath(channel)
    with open(path, 'r') as f:
        ret = f.readline()
    return ret



if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print "Usage (for output): usergpio.py channel state"
        sys.exit(1)
    set_value(int(sys.argv[1]), int(sys.argv[2]))
