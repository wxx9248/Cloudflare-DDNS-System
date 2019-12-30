#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
------------------------------------------------------
           Cloudflare DDNS system v2.0
                   by wxx9248

    Licensed under GNU General Public License v3.0
             Copyright 2020 © wxx9248
------------------------------------------------------
"""

__author__      = "wxx9248"
__copyright__   = "Copyright 2020 © wxx9248"
__license__     = "GPL v3"
__version__     = "v2.0"
__maintainer__  = [__author__]
__credits__     = [__author__]
__email__       = "wxx9248@qq.com"
__status__      = "Development"

import os, sys
import logging
import ctypes

def clrscr():
    dllname = "clrscr.dll"
    logger = logging.getLogger(__name__)
    
    try:
        dll = ctypes.CDLL(dllname)
    except Exception as e:
        logger.error("Can't load " + dllname + ": " + str(e))
    else:
        dll.clrscr()


def main():
    # Initialization
    userdata = {
        "E-mail":                 "",
        "Zone-ID":                "",
        "GlobalAPIMode":          False,
        "IPv6":                   True,
        "DNSAPIToken":            "",
        "GlobalAPIKey":           "",
        "Encrypted":              False
    }
    logging.basicConfig(level = logging.INFO, format = "[%(asctime)s] %(name)s: %(funcName)s(): [%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)

    # Start
    clrscr()
    print(sys.modules[__name__].__doc__)
    


if __name__ == "__main__":
    main()
