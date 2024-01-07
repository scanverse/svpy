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


# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Classifies the Vulnerability's Severity
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)

# scanverse Help Context
def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./sv.py example.com: Scans the domain example.com.")
        print("\t./sv.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
        print("\t./sv.py example.com --nospinner: Disable the idle loader/spinner.")
        print("\t./sv.py --update   : Updates the scanner to the latest version.")
        print("\t./sv.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits ScanVerse.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

# Scan Verse Logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = """
                                           ____                                 __  __                                 
                                          /\  _`\                              /\ \/\ \                                
                                          \ \,\L\_\    ___     __      ___     \ \ \ \ \     __   _ __   ____     __   
                                           \/_\__ \   /'___\ /'__`\  /' _ `\    \ \ \ \ \  /'__`\/\`'__\/',__\  /'__`\ 
                                             /\ \L\ \/\ \__//\ \L\.\_/\ \/\ \    \ \ \_/ \/\  __/\ \ \//\__, `\/\  __/ 
                                             \ `\____\ \____\ \__/.\_\ \_\ \_\    \ `\___/\ \____\\ \_\\/\____/\ \____\
                                              \/_____/\/____/\/__/\/_/\/_/\/_/     `\/__/  \/____/ \/_/ \/___/  \/____/
                                                                                                                       
                                                                             
    """
    print(logo_ascii)
    print(bcolors.ENDC)


# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            #for cursor in '|/-\\/': yield cursor #←↑↓→
            #for cursor in '←↑↓→': yield cursor
            #for cursor in '....scanning...please..wait....': yield cursor
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End ofloader/spinner class
