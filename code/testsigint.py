#!/usr/bin/env python
# coding=utf-8

# Credit to pklaus and adreif on github for the gist on which this server is based
# Found at: https://gist.github.com/pklaus/b5a7876d4d2cf7271873

import argparse
import datetime
import signal
import sys
import time
import threading
import traceback
import struct
import os


def main():
    

    status=dict(sigintted=False)
    def signal_handler(signal, frame):
            print('Received SIGINT from system')
            status["sigintted"]=True
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while not status["sigintted"]:
            time.sleep(1)
            print "Not sigintted"

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
