#!/usr/bin/python
# -*- coding: utf-8 -*-

r"""
------------------------------------------------------
            Cloudflare DDNS system v2.0
                    by wxx9248

    Licensed under GNU General Public License v3.0
              Copyright 2020 © wxx9248
------------------------------------------------------
"""

__author__      = r"wxx9248"
__copyright__   = r"Copyright 2020 © wxx9248"
__license__     = r"GPL v3"
__version__     = r"v2.0"
__maintainer__  = [__author__]
__credits__     = [__author__]
__email__       = r"wxx9248@qq.com"
__status__      = r"Development"

import os, sys
import json, base64, re, hashlib
import logging
import ctypes
import getpass
import urllib

try:
    from Crypto.Cipher import AES
except ImportError:
    print("The system depends on module \"PyCryptodome\".")
    print("Please install the module by executing \"pip install pycryptodome\".")
    print("Program will exit.")
    sys.exit(-1)


CONFPATH     = r"conf.json"
UNKNOWNEXMSG = r"Unknown exception occurred, referring to information below."
PASSWDREGMSG = r"""
Password must contain 8 - 32 characters, which consist of:
(1) a upper-case letter,
(2) a lower-case letter,
(3) a number,
(4) a special character (~!@&%#_)
"""

API_ROOT    = r"https://api.cloudflare.com/client/v4"


class Restart(Exception):
    pass

class ClientError(urllib.error.HTTPError):
    pass

class BadRequestError(ClientError):
    pass

class NotFoundError(ClientError):
    pass

class ForbiddenError(ClientError):
    pass

class ServerError(urllib.error.HTTPError):
    pass


regex_Email     = re.compile(r"^([\w\.]+)@(\w+)\.(\w+)$")
regex_hextoken  = re.compile(r"^([a-f0-9]{32})$")
regex_b64token  = re.compile(r"^([A-Za-z0-9\-\.\~\+/_]+)(=*)$")
regex_ZoneID    = regex_hextoken
regex_GAPIKey   = regex_hextoken
regex_DAPIToken = regex_b64token
regex_passwd    = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[~!@&%#_])[a-zA-Z0-9~!@&%#_]{8,32}$")

def main():
    # Initialization
    userdata = {
        "E-mail":                 "",
        "Zone-ID":                "",
        "GlobalAPIMode":          False,
        "APIKey":                 "",
        "IPv6":                   False,
        "Encrypted":              False,
        "EncryptTag":             "undefined",
        "OneTimeVal":             "undefined"
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
    except Exception:
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
            while True:
                try:
                    p = getpass.getpass("Please input your password: ").strip()
                    assert re.match(regex_passwd, p)
                except AssertionError:
                    print(PASSWDREGMSG)
                except Exception:
                    logger.error(UNKNOWNEXMSG)
                    raise
                else:
                    break

            logger.info("Decrypting...")
            try:
                userdata["APIKey"] = decrypt(
                    base64.b64decode(userdata["APIKey"].encode("utf-8")),
                    p,
                    base64.b64decode(userdata["EncryptTag"].encode("utf-8")),
                    base64.b64decode(userdata["OneTimeVal"].encode("utf-8"))
                    )
            except ValueError:
                logger.error("Incorrect password provided.")
            except Exception:
                logger.error(UNKNOWNEXMSG)
                raise
            else:
                logger.info("Decryption succeeded.")
                break
    else:
        logger.info("Encryption flag not detected, leaving as-is.")



def clrscr():
    dllname = "clrscr.dll"
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")
    
    try:
        dll = ctypes.CDLL(dllname)
        logger.debug("DLL attached.")
    except OSError:
        logger.warn("Can't load " + dllname)
        logger.warn("Invoking command line...")
        os.system("cls")
    except Exception:
        logger.error(UNKNOWNEXMSG)
        raise
    else:
        dll.clrscr()

def firstrun(userdata:dict):
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    while True:
        try:
            conffile = open(CONFPATH, "w")
        except OSError:
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
                        assert re.match(regex_Email, userdata["E-mail"])
                    except AssertionError:
                        print("Seemingly not an e-mail address, please try again.")
                    else:
                        break

                while True:
                    try:
                        userdata["Zone-ID"] = input("Please input the Zone-ID of your domain: ").strip()
                        assert re.match(regex_ZoneID, userdata["Zone-ID"])
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
                            assert re.match(regex_GAPIKey, userdata["APIKey"])
                        except AssertionError:
                            print("Seemingly not an proper API key, please try again.")
                        else:
                            break
                else:
                    userdata["GlobalAPIMode"] = False
                    while True:
                        try:
                            userdata["APIKey"] = input("Please input your DNS-dedicated API token: ").strip()
                            assert re.match(regex_DAPIToken, userdata["APIKey"])
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
                            assert re.match(regex_passwd, p)
                        except AssertionError:
                            print(PASSWDREGMSG)
                        else:
                            break

                clrscr()
                print("Information confirmation:\n")
                for i in ["{}: {}".format(k, userdata[k]) for k in userdata.keys()]:
                    print(i)
            
                choice = input("All correct (Y/N)? [Y]: ").strip()
                if choice != "" and choice[0] == "N":
                    raise Restart()
                else:
                    # TODO: Connect to Cloudflare server to verify the information user provided.

                    clrscr()
                    # Encrypt API key
                    if userdata["Encrypted"] == True:
                        bcipher, btag, bnonce = encrypt(userdata["APIKey"], p)
                        userdata["APIKey"] = base64.b64encode(bcipher).decode("utf-8")
                        userdata["EncryptTag"] = base64.b64encode(btag).decode("utf-8")
                        userdata["OneTimeVal"] = base64.b64encode(bnonce).decode("utf-8")
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
            

def encrypt(string:str, passwd:str):
    key = hashlib.shake_256(passwd.encode("utf-8")).hexdigest(8)    # 16-byte key
    crypto = AES.new(key.encode("utf-8"), AES.MODE_EAX)
    bnonce = crypto.nonce
    bcipher, btag = crypto.encrypt_and_digest(string.encode("utf-8"))

    return bcipher, btag, bnonce

def decrypt(bcipher:bytes, passwd:str, btag:bytes, bnonce:bytes):
    key = hashlib.shake_256(passwd.encode("utf-8")).hexdigest(8)
    crypto = AES.new(key.encode("utf-8"), AES.MODE_EAX, nonce = bnonce)
    string = crypto.decrypt(bcipher).decode("utf-8")
    crypto.verify(btag)

    return string

def conffileunparsable(conffile:_io.TextIOWrapper, userdata:dict):
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
       
def APItest(userdata:dict):
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    testAPIaddr = API_ROOT + "/zones/" + userdata["Zone-ID"]
    headers = { "Content-Type: application/json" }

    if userdata["GlobalAPIMode"]:
        logger.debug("Global API mode enabled.")
        headers.add("X-Auth-Email: " + userdata["E-mail"])
        headers.add("X-Auth-Key: " + userdata["APIKey"])
    else:
        headers.add("Authorization: Bearer " + userdata["APIKey"])

    # HTTP/GET request
    try:
        logger.info("Sending HTTPS request to Cloudflare...")
        raise Exception("TODO: Send GET request and process the JSON data.")
    except ConnectionError:
        logger.error("HTTPS request failed. Please check Internet connection.")
        raise
    except urllib.error.HTTPError:
        logger.error("HTTP error")
        raise Exception("TODO: Judge from the HTTP state code and throw a proper exception.")
        raise
    except Exception:
        logger.error("Unknown error occurred.")
        raise
    

if __name__ == "__main__":
    logging.basicConfig(level = logging.DEBUG, format = "[%(asctime)s] %(name)s: %(funcName)s(): [%(levelname)s] %(message)s")
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
