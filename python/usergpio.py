import os
import time
import struct

class gpiopin(object):
    _filename = None
    _fh = None
    _pin = None
    _inverted = False


    def __init__(self, pinnumber, dir="in", inverted=False):
        iodir = "/sys/class/gpio"
        self._filename = f"{iodir}/gpio{pinnumber}"
        #Export pin if not there
        if not os.path.isfile(f"{iodir}/gpio{pinnumber}/direction"):
            with open(f"{iodir}/export", "w") as f:
                f.write("%d\n" % pinnumber)
        with open(f"{iodir}/gpio{pinnumber}/direction", "w") as dirfile:
            dirfile.write(f"{dir}\n")
        if dir == "in":
            self._fh = open(f"{iodir}/gpio{pinnumber}/value", "rb", 0)
        else:
            self._fh = open(f"{iodir}/gpio{pinnumber}/value", "wb", 0)
        self._pin = pinnumber
        self._inverted = inverted

    def __del__(self):
        if self._fh:
            self._fh.close()
        
    def set(self, state):
        state = state^self._inverted
        if state:
            self._fh.write(b'1')
        else:
            self._fh.write(b'0')

    def get(self):
        self._fh.seek(0)
        if int(self._fh.read())^self._inverted:
            return 0
        return 1

RGBTABLE = {
    'R': [200, 0, 0],
    'r': [40, 0, 0],
    'G': [0, 255, 0],
    'g': [0, 60, 0],
    'B': [0, 0, 255],
    'b': [0, 0, 60],
    'y': [60, 40, 0],
    'Y': [255, 200, 0],
    'M': [200, 0, 255],
    'm': [40, 0, 60],
    'W': [255, 255, 255],
    'w': [60, 60, 60],
    ' ': [0,0,0],
    '.': [0,0,0]
}

class ledstring(object):
    _clkpin = None
    _datapin = None
    _nleds=1

    def __init__(self, data_pin=20, clk_pin=21, n=1):
        self._clk = gpiopin(clk_pin, "out")
        self._data = gpiopin(data_pin, "out")
        self._nleds = n

    def _out(self, data):
        for outbyte in data:
            for bit in range(7,-1,-1):
                self._clk.set(0)
                d=((outbyte&(1<<bit))>>bit)
                self._data.set(d)
                self._clk.set(1)
        self._clk.set(0)

    def _send_rgb(self,r,g,b):
        current = 16 #out of 31
        #Send global current + 3 PWM values with 0b111 starting bits
        self._out(struct.pack("BBBB", 224+current, b, g, r))

    def _start_of_frame(self):
        self._out(b"\x00\x00\x00\x00")

    def _end_of_frame(self):
        self._out(b"\xff\xff\xff\xff")
        
    def set_all_rgb(self, r,g,b):
        self._start_of_frame()
        for ledno in range(self._nleds):
            self._send_rgb(r,g,b)
        self._end_of_frame()
        self._start_of_frame()
        self._start_of_frame()

    #Sets LEDs with string like "RRRGGGBBB"
    def setstr(self, colors):
        self._start_of_frame()
        for c in colors:
            self._send_rgb(RGBTABLE[c][0], RGBTABLE[c][1], RGBTABLE[c][2])
        self._end_of_frame()
        #self._start_of_frame()
        #self._start_of_frame()

if __name__ == "__main__":
    relay = gpiopin(4, dir="out")
    buzzer = gpiopin(12, dir="out")
    led_clk = gpiopin(20, dir="out")
    led_data = gpiopin(21, dir="out")
    latch = gpiopin(17, dir="in")
    door = gpiopin(18, dir="in")
    b1 = gpiopin(22, dir="in")
    b2 = gpiopin(23, dir="in")
    handle = gpiopin(27, dir="in")
    
    for i in range(100):
        relay.set(0)
        #buzzer.set(0)
        time.sleep(0.5)
        relay.set(1)
        #buzzer.set(1)
        time.sleep(0.5)

        print(f"latch={latch.get()} door={door.get()} handle={handle.get()} b1={b1.get()} b2={b2.get()}")
        
