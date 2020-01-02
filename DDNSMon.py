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
import json
import logging
import ctypes
import re

CONFPATH     = "conf.json"
UNKNOWNEXMSG = "Unknown exception occurred, referring to information below."


def main():
    # Initialization
    userdata = {
        "E-mail":                 "",
        "Zone-ID":                "",
        "GlobalAPIMode":          False,
        "IPv6":                   False,
        "DNSAPIToken":            "",
        "GlobalAPIKey":           "",
        "Encrypted":              False
    }
    logger = logging.getLogger(__name__)

    # Start
    clrscr()
    print(sys.modules[__name__].__doc__)
    
    try:
        conffile = open(CONFPATH)
    except FileNotFoundError:
        # First run
        logger.info("Configure file not found.")
        logger.info("Entering first-run configuration...")
        firstrun()
    except OSError as e:
        logger.error("Can't open configure file \"{}\" for reading".format(CONFPATH))
        raise
    except Exception as e:
        logger.error(UNKNOWNEXMSG)
        raise


def clrscr():
    dllname = "clrscr.dll"
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")
    
    try:
        dll = ctypes.CDLL(dllname)
        logger.debug("DLL attached.")
    except OSError as e:
        logger.error("Can't load " + dllname)
    except Exception:
        logger.error(UNKNOWNEXMSG)
        raise
    else:
        dll.clrscr()

def firstrun():
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    try:
        conffile = open(CONFPATH, "w")
    except OSError as e:
        logger.error("Can't open configure file \"{}\" for writing".format(CONFPATH))
        raise
    except Exception:
        logger.error(UNKNOWNEXMSG)
        raise


if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO, format = "[%(asctime)s] %(name)s: %(funcName)s(): [%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    try:
        main()
    except Exception as e:
        logger.error("*********************************")
        logger.error("A fatal error has occurred below:\n")
        logger.error(re.search(r"<class '(.+)'>", str(e.__class__)).group(1) + ": " + str(e) + "\n")
        logger.error("Program exits abnormally.")
        logger.error("*********************************")

