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

class Restart(Exception):
    pass

def main():
    # Initialization
    userdata = {
        "E-mail":                 "",
        "Zone-ID":                "",
        "GlobalAPIMode":          False,
        "APIKey":                 "",
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
        logger.info("Configure file not found.")
        logger.info("Entering first-run configuration...")
        firstrun(userdata)
        conffile = open(CONFPATH)
    except OSError:
        logger.error("Can't open configure file \"{}\" for reading, referring to information below.".format(CONFPATH))
        raise
    except Exception as e:
        logger.error(UNKNOWNEXMSG)
        raise
    
    logger.info("Parsing configuration file...")
    try:
        tmpdata = json.load(conffile)
    except Exception:
        logger.error("Failed to parse configuration file.")
        conffileunparsable(conffile, userdata)

    logger.info("Checking integrity...")
    try:
        assert set(userdata.keys()).issubset(set(tmpdata.keys()))
        for i in tmpdata:
            if isinstance(tmpdata[i], str):
                assert tmpdata[i]
            else:
                assert tmpdata[i] != None
    except AssertionError:
        logger.error("Integrity verification failed.")
        conffileunparsable(conffile, userdata)
    else:
        userdata = tmpdata

    logger.info("Checking if encrypted...")
    if userdata["Encrypted"]:
        logger.info("Encryption flag detected, starting decryption process.")
        while True:
            try:
                p = input("Please input your password: ").strip()
                assert p.printable()
            except AssertionError:
                print("Only printable password allowed, please try again.")
            except Exception:
                logger.error(UNKNOWNEXMSG)
                raise
            else:
                break
        
        logger.info("Decrypting...")
        try:
            userdata["APIKey"] = decrypt(base64.b64decode(bytes(userdata["APIKey"])), p)
        except Exception:
            logger.error("Decryption process failed.")
            conffileunparsable(conffile, userdata)
        else:
            logger.info("Decryption succeeded.")

    else:
        logger.info("Encryption flag not detected, leaving as-is.")


def clrscr():
    dllname = "clrscr.dll"
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")
    
    try:
        dll = ctypes.CDLL(dllname)
        logger.debug("DLL attached.")
    except OSError as e:
        logger.warn("Can't load " + dllname)
        logger.warn("Invoking command line...")
        os.system("cls")
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
            logger.error("Can't open configure file \"{}\" for writing, referring to information below.".format(CONFPATH))
            raise
        except Exception:
            logger.error(UNKNOWNEXMSG)
            raise
        else:
            try:
                while True:
                    try:
                        userdata["E-mail"] = input("Please input the e-mail address of your Cloudflare account: ").strip()
                        assert re.match(r"^([A-Za-z0-9]+)@([A-Za-z0-9]+)\.([A-Za-z0-9]+$)", userdata["E-mail"])
                    except AssertionError:
                        print("Seemingly not an e-mail address, please try again.")
                    else:
                        break

                while True:
                    try:
                        userdata["Zone-ID"] = input("Please input the Zone-ID of your domain: ").strip()
                        assert re.match(r"^([a-z0-9]+$)", userdata["Zone-ID"])
                    except AssertionError:
                        print("Seemingly not an proper Zone-ID, please try again.")
                    else:
                        break
                
                print("Do you wish to use your global API key?")
                print("ATTENTION! GLOBAL API KEY LEAKAGE WILL THREATEN YOUR *WHOLE* CLOUDFLARE ACCOUNT!")
                choice = input("Your choice (Y/N)? [N]: ").strip()
                if choice != "" and choice[0] == "Y":
                    userdata["GlobalAPIMode"] = True
                    userdata["Encrypted"] = True
                    print("To ensure the safety of your API key, configuration file encryption will be forced.")
                    while True:
                        try:
                            userdata["APIKey"] = input("Please input your global API key: ").strip()
                            assert re.match(r"^([a-z0-9]+$)", userdata["APIKey"])
                        except AssertionError:
                            print("Seemingly not an proper API key, please try again.")
                        else:
                            break
                else:
                    userdata["GlobalAPIMode"] = False
                    while True:
                        try:
                            userdata["APIKey"] = input("Please input your DNS-dedicated API token: ").strip()
                            assert re.match(r"^([A-Za-z0-9\-\.\~\+/_]+)(=*)$", userdata["APIKey"])
                        except AssertionError:
                            print("Seemingly not an proper API key, please try again.")
                        else:
                            break

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
                    while True:
                        try:
                            p = input("Please input your password: ").strip()
                            assert p.isprintable()
                        except AssertionError:
                            print("Only printable password allowed, please try again.")
                        else:
                            break

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
                        userdata["APIKey"] = str(base64.b64encode(encrypt(userdata["APIKey"], p)))
                        p = ""
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
            else:
                break
        finally:
            conffile.close()
            

def encrypt(string, key):
    return bytes(string, "utf-8")

def decrypt(bstring, key):
    return str(bstring)

def conffileunparsable(conffile, userdata):
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    logger.info("Closing file...")
    conffile.close()
    logger.error("Can't parse configuration file, asking for reconfiguration.")
    print("The configuration file seems corrupted or unparsable.")
    choice = input("Do you wish to re-setup the program (Y/N)? [Y]: ").strip()
    if choice != "" and choice[0] == "N":
        print("You denied reconfiguration.")
        raise
    else:
        firstrun(userdata)
        raise Restart()
        


if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO, format = "[%(asctime)s] %(name)s: %(funcName)s(): [%(levelname)s] %(message)s")
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    while True:
        try:
            main()
        except Restart:
            logger.info("Restarting into program entry point...")
        except Exception as e:
            print("")
            logger.error("*********************************")
            logger.error("An fatal exception has occurred:\n")
            logger.error(re.search(r"<class '(.+)'>", str(e.__class__)).group(1) + ": " + str(e) + "\n")
            logger.error("Program exits abnormally.")
            logger.error("*********************************")
            break
        except BaseException as e:
            print("")
            logger.error("==============================")
            logger.error("Program was terminated due to:\n")
            logger.error(re.search(r"<class '(.+)'>", str(e.__class__)).group(1) + ": " + str(e) + "\n")
            logger.error("==============================")
            break
        else:
            break
