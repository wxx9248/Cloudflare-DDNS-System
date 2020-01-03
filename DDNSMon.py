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
import json, base64
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
        "DNSAPIToken":            "",
        "GlobalAPIKey":           "",
        "IPv6":                   False,
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
        firstrun(userdata)
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

def firstrun(userdata):
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    while True:
        try:
            conffile = open(CONFPATH, "w")
        except OSError as e:
            logger.error("Can't open configure file \"{}\" for writing".format(CONFPATH))
            raise
        except Exception:
            logger.error(UNKNOWNEXMSG)
            raise
        else:
            try:
                while True:
                    try:
                        userdata["E-mail"] = input("Please input the e-mail address of your Cloudflare account: ").strip()
                        assert re.search(r"([A-Za-z0-9]+)@([A-Za-z0-9]+)\.([A-Za-z0-9]+)", userdata["E-mail"]) != None
                    except AssertionError:
                        print("Seemingly not an e-mail address, please try again.")
                    else:
                        break

                userdata["Zone-ID"] = input("Please input the Zone-ID of your domain: ").strip()

                print("Do you wish to use your global API key?")
                print("ATTENTION! GLOBAL API KEY LEAKAGE WILL THREATEN YOUR *WHOLE* CLOUDFLARE ACCOUNT!")
                choice = input("Your choice (Y/N)? [N]: ").strip()
                if choice != "" and choice[0] == "Y":
                    userdata["GlobalAPIMode"] = True
                    userdata["Encrypted"] = True
                    print("To ensure the safety of your API key, configuration file encryption will be forced.")
                    userdata["GlobalAPIKey"] = input("Please input your global API key: ").strip()
                else:
                    userdata["GlobalAPIMode"] = False
                    userdata["DNSAPIToken"] = input("Please input your DNS-dedicated API token: ").strip()

                choice = input("Do you wish to enable IPv6 support (Y/N)? [N]: ").strip()

                if choice != "" and choice[0] == "Y":
                    userdata["IPv6"] = True
                else:
                    userdata["IPv6"] = False

                if userdata["GlobalAPIMode"] == False:
                    choice = input("Do you wish to enable configuration file encryption (Y/N)? [Y]: ").strip()
                    if choice != "" and choice[0] == "N":
                        userdata["Encrypted"] = False
                    else:
                        userdata["Encrypted"] = True

                if userdata["Encrypted"] == True:
                    p = input("Please input your password: ").strip()

                clrscr()
                print("Information confirmation:\n")
                for i in ["{}: {}".format(k, userdata[k]) for k in userdata.keys()]:
                    print(i)
            
                choice = input("All correct (Y/N)? [Y]: ").strip()
                if choice != "" and choice[0] == "N":
                    clrscr()
                else:
                    # Encrypt API key
                    if userdata["Encrypted"] == True:
                        if userdata["GlobalAPIMode"] == True:
                            userdata["GlobalAPIKey"] = str(base64.b64encode(encrypt(userdata["GlobalAPIKey"], p)))
                        else:
                            userdata["DNSAPIToken"] = str(base64.b64encode(encrypt(userdata["DNSAPIToken"], p)))

                    # Write configure to JSON file
                    try:
                        json.dump(userdata, conffile, indent = 4)
                    except OSError:
                        logger.error("Can't generate configuration file, referring to information below.")
                        raise
                    except Exception:
                        logger.error(UNKNOWNEXMSG)
                        raise
            except BaseException:
                conffile.close()
                os.remove(CONFPATH)
                raise
        finally:
            conffile.close()
            

def encrypt(string, key):
    return bytes(string, "utf-8")

def decrypt(bstring, key):
    return str(bstring)

if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO, format = "[%(asctime)s] %(name)s: %(funcName)s(): [%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    try:
        main()
    except Exception as e:
        print("")
        logger.error("*********************************")
        logger.error("An fatal exception has occurred:\n")
        logger.error(re.search(r"<class '(.+)'>", str(e.__class__)).group(1) + ": " + str(e) + "\n")
        logger.error("Program exits abnormally.")
        logger.error("*********************************")
    except BaseException as e:
        print("")
        logger.error("==============================")
        logger.error("Program was terminated due to:\n")
        logger.error(re.search(r"<class '(.+)'>", str(e.__class__)).group(1) + ": " + str(e) + "\n")
        logger.error("==============================")
