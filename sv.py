#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ____                   __     __                 
#  / ___|  ___ __ _ _ __   \ \   / /__ _ __ ___  ___ 
#  \___ \ / __/ _` | '_ \   \ \ / / _ \ '__/ __|/ _ \
#   ___) | (_| (_| | | | |   \ V /  __/ |  \__ \  __/
#  |____/ \___\__,_|_| |_|    \_/ \___|_|  |___/\___|
#                                                    
# Author     : Anubhav Gain
# Tool       : ScanVerse
# Usage      : python3 sv.py example.com
# Description: This scanner automates the process of security scanning by using a
#              multitude of available linux security tools and some custom scripts.
#

# Importing the libraries
import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit


CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val
