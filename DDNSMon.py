#!/usr/bin/env python
# -*- coding: utf-8 -*-

r"""
------------------------------------------------------
            Cloudflare DDNS system v2.0
                    by wxx9248

    Licensed under GNU General Public License v3.0
              Copyright 2020 © wxx9248
------------------------------------------------------
"""

__author__ = r"wxx9248"
__copyright__ = r"Copyright 2020 © wxx9248"
__license__ = r"GPL v3"
__version__ = r"v2.0.1"
__maintainer__ = [__author__]
__credits__ = [__author__]
__email__ = r"wxx9248@qq.com"
__status__ = r"Release"

import abc
import base64
import ctypes
import getpass
import hashlib
import json
import logging
import os
import pprint
import re
import sys
import time
import traceback
import urllib.error
import urllib.request
import urllib.parse

try:
    import HTTPErrors
except ImportError:
    print("Cannot find component \"HTTPErrors.py\".")
    print("Program will exit.")
    sys.exit(-1)

try:
    from Crypto.Cipher import AES
except ImportError:
    print("The system depends on module \"PyCryptodome\".")
    print("Please install the module by executing \"pip install pycryptodome\".")
    print("Program will exit.")
    sys.exit(-1)

CONFPATH = r"conf.json"
UNKNOWNEXMSG = r"Unknown exception occurred, referring to information below."
PASSWDREGMSG = r"""
Password must contain 8 - 32 characters, which consist of:
(1) a upper-case letter,
(2) a lower-case letter,
(3) a number,
(4) a special character (~!@&%#_)
"""

CF_API_ROOT = r"https://api.cloudflare.com/client/v4"
IP_API_ROOT = r"https://api.ipify.org?format=json"
IP6_API_ROOT = r"https://api6.ipify.org?format=json"

PASSWDATT_UPB = 10
NETFAILATT_UPB = 3

SLEEPSEC = 60 * 30  # 30 minutes


class Restart(Exception):
    pass


class MException(Exception, abc.ABC):
    def __init__(self, ofailed):
        super().__init__()
        self.ofailed = ofailed

    @abc.abstractmethod
    def errormsg(self):
        """
        Return a string formatted from ofailed.
        :return: str
        """
        pass


class APIFailed(MException):
    def __init__(self, ofailed: dict):
        super().__init__(ofailed)

    def errormsg(self):
        return pprint.pformat(self.ofailed)


class JSONFailed(MException):
    def __init__(self, ofailed: json.JSONDecodeError):
        super().__init__(ofailed)

    def errormsg(self):
        head = "Decode failed in line {}, column {}".format(
            self.ofailed.lineno, self.ofailed.colno
        )
        body = ""
        for i, line in enumerate(str(self.ofailed.doc).splitlines()):
            body += "{}: {}\n".format(i, line)
        return head + "\n\n" + body


class ConfFileDamaged(Exception):
    def __init__(self, userdata: dict):
        super().__init__()
        assert userdata
        self._userdata = userdata

    def deal(self):
        logger = logging.getLogger(__name__)
        logger.debug("Logger initialized.")

        if hasattr(self, "_userdata"):
            choice = input("Do you wish to re-setup the program (Y/N)? [Y]: ").strip().upper()
            if choice != "" and choice[0] == "N":
                logger.warning("User denied to reconfigure.")
                raise
            else:
                firstrun(self._userdata)
                raise Restart()
        else:
            # As a class in Python, I feel so unsafe...
            logger.error("That's ILLEGAL!")
            raise Exception("RU kiddin' me?")


regex_Domain = re.compile(r"^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$")
regex_Email = re.compile(r"^([\w.]+)@(\w+)\.(\w+)$")
regex_hextoken = re.compile(r"^([a-f0-9]{32})$")
regex_b64token = re.compile(r"^([A-Za-z0-9\-.~+/_]+)(=*)$")
regex_ZoneID = regex_hextoken
regex_GAPIKey = regex_hextoken
regex_DAPIToken = regex_b64token
regex_passwd = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[~!@&%#_])[a-zA-Z0-9~!@&%#_]{8,32}$")


def main():
    # Initialization
    userdata = {
        "Zone-ID":       "",
        "Domains":       [],
        "GlobalAPIMode": False,
        "E-mail":        "undefined",
        "APIKey":        "",
        "IPv6":          False,
        "Encrypted":     False,
        "EncryptTag":    "undefined",
        "OneTimeVal":    "undefined"
    }
    logger = logging.getLogger(__name__)

    # Start
    clrscr()
    print(sys.modules[__name__].__doc__)

    while True:
        try:
            with open(CONFPATH) as conffile:
                logger.info("Parsing configuration file...")
                tmpdata = json.load(conffile)
        except FileNotFoundError:
            logger.warning("Configure file not found.")
            logger.debug("Entering first-run configuration...")
            firstrun(userdata)
        except OSError:
            logger.error(
                "Can't open configure file \"{}\" for reading, referring to information below.".format(CONFPATH))
            raise
        except json.JSONDecodeError as e:
            logger.error("Failed to parse configuration file. Detailed reason:")
            logger.error(JSONFailed(e).errormsg())
            ConfFileDamaged(userdata).deal()
        except Exception:
            logger.error(UNKNOWNEXMSG)
            raise
        else:
            break

    logger.info("Checking integrity...")
    try:
        logger.debug("Stage 1: Check if empty or invalid.")
        assert set(userdata.keys()).issubset(set(tmpdata.keys()))
        for i in tmpdata:
            if isinstance(tmpdata[i], str):
                assert tmpdata[i]
            elif isinstance(tmpdata[i], list):
                assert tmpdata[i]
                for item in tmpdata[i]:
                    assert isinstance(item, str)
                    assert item
            else:
                assert tmpdata[i] is not None

        logger.debug("Stage 2: Regex-matching check.")

        assert re.match(regex_ZoneID, tmpdata["Zone-ID"])
        logger.debug("Zone-ID: pass")

        for item in tmpdata["Domains"]:
            assert re.match(regex_Domain, item)
        logger.debug("Domains: pass")

        if tmpdata["GlobalAPIMode"]:
            assert tmpdata["Encrypted"] is not None
            logger.debug("Encrypted: pass")
            assert re.match(regex_Email, tmpdata["E-mail"])
            logger.debug("E-mail: pass")

        if tmpdata["Encrypted"] or not tmpdata["GlobalAPIMode"]:
            assert re.match(regex_DAPIToken, tmpdata["APIKey"])
            logger.debug("APIKey 1st check: pass")

        if tmpdata["Encrypted"]:
            assert re.match(regex_b64token, tmpdata["EncryptTag"])
            logger.debug("EncryptTag: pass")
            assert re.match(regex_b64token, tmpdata["OneTimeVal"])
            logger.debug("OneTimeVal: pass")

    except AssertionError:
        logger.error("Integrity verification failed.")
        ConfFileDamaged(userdata).deal()
    else:
        userdata = tmpdata

    logger.info("Checking if encrypted...")
    if userdata["Encrypted"]:
        logger.info("Encryption flag detected, starting decryption process.")
        attempts = 0

        while True:
            while True:
                try:
                    p = getpass.getpass("Please input your password: ").strip()
                    assert re.match(regex_passwd, p)
                except AssertionError:
                    logger.error("Invalid password provided")
                    logger.info(PASSWDREGMSG)
                except Exception:
                    logger.error(UNKNOWNEXMSG)
                    raise
                else:
                    break

            attempts += 1
            logger.info("Decrypting...")
            try:
                userdata["APIKey"] = decrypt(
                    base64.b64decode(userdata["APIKey"].encode("utf-8")),
                    p,
                    base64.b64decode(userdata["EncryptTag"].encode("utf-8")),
                    base64.b64decode(userdata["OneTimeVal"].encode("utf-8"))
                )
                # Regex-matching check
                if userdata["GlobalAPIMode"]:
                    assert re.match(regex_GAPIKey, userdata["APIKey"])
                else:
                    assert re.match(regex_DAPIToken, userdata["APIKey"])
                logger.debug("APIKey 2nd check: pass")
                del p
            except ValueError:
                if attempts < PASSWDATT_UPB:
                    logger.error("Attempt {} of {} :".format(attempts, PASSWDATT_UPB))
                    logger.error("Incorrect password provided, please try again.")
                else:
                    logger.error("Please consider configuration file corruption.")
                    ConfFileDamaged(userdata).deal()
            except AssertionError:
                logger.error("APIKey 2nd check: failed")
                ConfFileDamaged(userdata).deal()
            except Exception:
                logger.error(UNKNOWNEXMSG)
                raise
            else:
                logger.info("Decryption succeeded.")
                break
    else:
        logger.info("Encryption flag not detected, leaving as-is.")

    IPv6_address = None
    target_A_records = {}
    target_AAAA_records = {}

    attempts = 0
    switchbit = True
    while True:
        try:
            # Get current IP address
            logger.info("Getting current IPv4 address")
            response = json.loads(APIreq(IP_API_ROOT).read().decode())
            if response and response["ip"]:
                IPv4_address = response["ip"]
                logger.info("IPv4 OK: {}".format(IPv4_address))
            else:
                raise APIFailed(response)

            if userdata["IPv6"]:
                logger.info("Getting current IPv6 address")
                response = json.loads(APIreq(IP6_API_ROOT).read().decode())
                if response and response["ip"]:
                    if response["ip"] != IPv4_address:
                        IPv6_address = response["ip"]
                        logger.info("IPv6 OK: {}".format(IPv6_address))
                    else:
                        logger.warning("IPv6 network not detected")
                        userdata["IPv6"] = False
                        logger.warning("IPv6 temporarily disabled")
                else:
                    raise APIFailed(response)

            logger.debug("switchbit: {}".format(switchbit))

            if switchbit:
                target_iter_v4 = target_iter_v6 = userdata["Domains"]
            else:
                target_iter_v4 = target_A_records
                target_iter_v6 = target_AAAA_records

            for domain in target_iter_v4:
                # A records
                # GET zones/:zone_identifier/dns_records
                logger.info("Getting IPv4 address of domain {} on record".format(domain))
                response = json.loads(APIreq(
                    "{}/zones/{}/dns_records?{}={}&{}={}".format(
                        CF_API_ROOT, userdata["Zone-ID"],
                        "name", domain,
                        "type", "A"
                    ), userdata = userdata).read().decode())

                if not response["success"]:
                    logger.error("Cloudflare API failed")
                    raise APIFailed(response)
                elif response["result"]:
                    target_A_records[domain] = {
                        "id":      response["result"][0]["id"],
                        "content": response["result"][0]["content"]
                    }
                    logger.info("Identifier of domain {}: {}".format(domain, target_A_records[domain]["id"]))
                    logger.info("IPv4 of domain {}: {}".format(domain, target_A_records[domain]["content"]))
                else:
                    logger.warning("A record of domain {}: Not Found".format(domain))
                    logger.warning("Temporarily disabled DDNSv4 service for this domain")

            # AAAA records
            if userdata["IPv6"]:
                for domain in target_iter_v6:
                    logger.info("Getting IPv6 address of domain {} on record".format(domain))
                    response = json.loads(APIreq(
                        "{}/zones/{}/dns_records?{}={}&{}={}".format(
                            CF_API_ROOT, userdata["Zone-ID"],
                            "name", domain,
                            "type", "AAAA"
                        ), userdata = userdata).read().decode())

                    if not response["success"]:
                        logger.error("Cloudflare API failed")
                        raise APIFailed(response)
                    elif response["result"]:
                        target_AAAA_records[domain] = {
                            "id":      response["result"][0]["id"],
                            "content": response["result"][0]["content"]
                        }
                        logger.info("Identifier of domain {}: {}".format(domain, target_AAAA_records[domain]["id"]))
                        logger.info("IPv6 of domain {}: {}".format(domain, target_AAAA_records[domain]["content"]))
                    else:
                        logger.warning("AAAA record of domain {}: Not Found".format(domain))
                        logger.warning("Temporarily disabled DDNSv6 service for this domain")

            switchbit = False

            # Assessment
            # Change records if different
            # v4
            for domain in target_A_records:
                if target_A_records[domain]["content"] != IPv4_address:
                    response = json.loads(APIreq(
                        "{}/zones/{}/dns_records/{}".format(
                            CF_API_ROOT, userdata["Zone-ID"], target_A_records[domain]["id"]
                        ), userdata = userdata, method = "PUT", data = json.dumps(
                            {
                                "name":    domain,
                                "type":    "A",
                                "content": IPv4_address
                            }).encode()).read().decode()
                                          )
                    try:
                        assert response
                        assert response["success"]
                        assert response["result"]["id"] == target_A_records[domain]["id"]
                        assert response["result"]["type"] == "A"
                        assert response["result"]["name"] == domain
                        assert response["result"]["content"] == IPv4_address
                    except AssertionError:
                        logger.error("Cloudflare API failed")
                        raise APIFailed(response)
                    logger.info("IPv4 for domain {} changed to {}".format(domain, IPv4_address))
                else:
                    logger.info("IPv4 for domain {} matches current IPv4 {}".format(domain, IPv4_address))
                    logger.info("No need to change.")
                logger.info("Proceeding to next step")

            # v6
            if userdata["IPv6"]:
                for domain in target_AAAA_records:
                    if target_AAAA_records[domain]["content"] != IPv6_address:
                        response = json.loads(APIreq(
                            "{}/zones/{}/dns_records/{}".format(
                                CF_API_ROOT, userdata["Zone-ID"], target_AAAA_records[domain]["id"]
                            ), userdata = userdata, method = "PUT", data = json.dumps(
                                {
                                    "name":    domain,
                                    "type":    "AAAA",
                                    "content": IPv6_address
                                }).encode()).read().decode()
                                              )
                        try:
                            assert response
                            assert response["success"]
                            assert response["result"]["id"] == target_AAAA_records[domain]["id"]
                            assert response["result"]["type"] == "AAAA"
                            assert response["result"]["name"] == domain
                            assert response["result"]["content"] == IPv6_address
                        except AssertionError:
                            logger.error("Cloudflare API failed")
                            raise APIFailed(response)
                        logger.info("IPv6 for domain {} changed to {}".format(domain, IPv6_address))
                    else:
                        logger.info("IPv6 for domain {} matches current IPv6 {}".format(domain, IPv6_address))
                        logger.info("No need to change.")
                    logger.info("Proceeding to next step")

            # Sleep
            logger.info("Sleep for %d:%02d:%02d" % (SLEEPSEC // 3600, SLEEPSEC // 60 % 60, SLEEPSEC % 60))
            time.sleep(SLEEPSEC)

        except (
                HTTPErrors.RequestTimeOutError, HTTPErrors.ServiceUnavailableError,
                HTTPErrors.GatewayTimeOutError, HTTPErrors.TooManyRequestsError) as e:
            logger.error("Request failed, reason: " + str(e) + ". Will try again later.")
        except HTTPErrors.InternalServerError as e:
            if attempts < NETFAILATT_UPB:
                logger.error("Request failed, reason: " + str(e) + ". Will try another " + str(attempts) + " time(s).")
                attempts += 1
            else:
                logger.error("Request failed, reason: " + str(e))
                logger.error("API might be changed. Please send this log to " + __email__)
                raise
        except (HTTPErrors.UnauthorizedError, HTTPErrors.ForbiddenError) as e:
            logger.error("Request failed, reason: " + str(e))
            logger.error("Your credentials may be incorrect.")
            while True:
                choice = input("Try again or reconfigure (T/R)? [T]: ").strip().upper()
                if choice != "" and choice[0] == 'R':
                    ConfFileDamaged(userdata).deal()
                else:
                    break
        except (HTTPErrors.ClientError, HTTPErrors.ServerError) as e:
            logger.error("Request failed, reason: " + str(e))
            logger.error("API might be changed. Please send this log to " + __email__)
            raise
        except urllib.error.URLError:
            logger.error("Internet unavailable. Will try again later.")
        except json.JSONDecodeError as e:
            logger.error("JSON decode failed.")
            raise JSONFailed(e)
        except Exception:
            logger.error(UNKNOWNEXMSG)
            raise


def clrscr():
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    try:
        if "win32" in sys.platform:
            os.system("CLS")
        else:
            os.system("clear")
    except OSError:
        logger.warning("Cannot invoke system call")
    except Exception:
        logger.error(UNKNOWNEXMSG)
        raise


def firstrun(userdata: dict):
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    while True:
        try:
            with open(CONFPATH, "w") as conffile:
                while True:
                    try:
                        userdata["Zone-ID"] = input("Please input the Zone-ID of your domain: ").strip()
                        assert re.match(regex_ZoneID, userdata["Zone-ID"])
                    except AssertionError:
                        logger.error("Invalid Zone-ID provided.")
                    else:
                        break

                while True:
                    try:
                        domain = input("Please input targeted domain name: ").strip().lower()
                        assert re.match(regex_Domain, domain)
                        userdata["Domains"].append(domain)
                    except AssertionError:
                        logger.error("Invalid domain name provided.")
                    else:
                        choice = input("Do you wish to add another domain name (Y/N)? [N]: ").strip().upper()
                        if choice != "" and choice[0] == 'Y':
                            pass
                        else:
                            break

                logger.info("Do you wish to use your global API key?")
                logger.warning("ATTENTION! GLOBAL API KEY LEAKAGE WILL THREATEN YOUR *WHOLE* CLOUDFLARE ACCOUNT!")
                choice = input("Your choice (Y/N)? [N]: ").strip().upper()
                if choice != "" and choice[0] == "Y":
                    logger.warning("Global API mode activated.")
                    userdata["GlobalAPIMode"] = True
                    userdata["Encrypted"] = True
                    logger.info("To ensure the safety of your API key, configuration file encryption will be forced.")
                    while True:
                        try:
                            userdata["E-mail"] = input(
                                "Please input the e-mail address of your Cloudflare account: ").strip()
                            assert re.match(regex_Email, userdata["E-mail"])
                        except AssertionError:
                            logger.error("Invalid e-mail address provided.")
                        else:
                            break

                    while True:
                        try:
                            userdata["APIKey"] = input("Please input your global API key: ").strip()
                            assert re.match(regex_GAPIKey, userdata["APIKey"])
                        except AssertionError:
                            logger.error("Invalid API key provided.")
                        else:
                            break
                else:
                    userdata["GlobalAPIMode"] = False
                    while True:
                        try:
                            userdata["APIKey"] = input("Please input your DNS-dedicated API token: ").strip()
                            assert re.match(regex_DAPIToken, userdata["APIKey"])
                        except AssertionError:
                            logger.error("Invalid API key provided.")
                        else:
                            break

                choice = input("Do you wish to enable IPv6 support (Y/N)? [N]: ").strip().upper()

                if choice != "" and choice[0] == "Y":
                    logger.debug("IPv6 support enabled.")
                    userdata["IPv6"] = True
                else:
                    logger.debug("IPv6 support disabled.")
                    userdata["IPv6"] = False

                if not userdata["GlobalAPIMode"]:
                    choice = input("Do you wish to enable API key encryption (Y/N)? [Y]: ").strip().upper()
                    if choice != "" and choice[0] == "N":
                        logger.debug("API key encryption disabled")
                        userdata["Encrypted"] = False
                    else:
                        logger.debug("API key encryption enabled")
                        userdata["Encrypted"] = True

                if userdata["Encrypted"]:
                    while True:
                        try:
                            p = input("Please input your password: ").strip()
                            assert re.match(regex_passwd, p)
                        except AssertionError:
                            logger.error("Invalid password provided")
                            logger.info(PASSWDREGMSG)
                        else:
                            break

                clrscr()
                logger.info("Information confirmation:\n")
                printconf(userdata)

                choice = input("All correct (Y/N)? [Y]: ").strip().upper()
                if choice != "" and choice[0] == "N":
                    logger.warning("User denied to proceed, restarting program.")
                    raise Restart()
                else:
                    attempts = 0
                    while True:
                        try:
                            APIreq(CF_API_ROOT + "/zones/" + userdata["Zone-ID"], userdata = userdata)
                            break

                        except urllib.error.URLError:
                            logger.warning("Internet currently unavaliable. Cannot verify information correctness.")
                            logger.warning("Configure file will be generated as-is.")
                            break

                        except (HTTPErrors.BadRequestError, HTTPErrors.UnauthorizedError, HTTPErrors.ForbiddenError):
                            logger.warning("Server API returned exceptional code.")
                            logger.warning("May be information mismatch.")

                            choice = input("Try to send request again or re-setup (T/R)? [T]: ").strip().upper()
                            if choice != "" and choice[0] == "R":
                                raise Restart()

                        except (HTTPErrors.NotFoundError, HTTPErrors.MethodNotAllowedError,
                                HTTPErrors.NotImplementedError, HTTPErrors.UnsupportedMediaTypeError):
                            logger.error("Invalid server API.")
                            logger.error(
                                "Please open an issue at the Github page of this project and attach this log "
                                "file.")
                            raise

                        except (HTTPErrors.RequestTimeOutError, HTTPErrors.ServiceUnavailableError,
                                HTTPErrors.GatewayTimeOutError, HTTPErrors.TooManyRequestsError):
                            attempts += 1
                            if attempts > NETFAILATT_UPB:
                                logger.warning(
                                    "Maximum connection failure times reached. Cannot verify information correctness.")
                                logger.warning("Configure file will be generated as-is.")
                                break
                            else:
                                logger.warning("Attempt #{}: Request not reached, retry.".format(attempts))

                        except (HTTPErrors.ServerError, HTTPErrors.ClientError):
                            logger.warning(
                                "Unable to connect to Cloudflare server. Cannot verify information correctness.")
                            logger.warning("Configure file will be generated as-is.")
                            break

                        except Exception:
                            logger.error(UNKNOWNEXMSG)
                            raise

                    clrscr()
                    # Encrypt API key
                    if userdata["Encrypted"]:
                        bcipher, btag, bnonce = encrypt(userdata["APIKey"], p)
                        del p
                        userdata["APIKey"] = base64.b64encode(bcipher).decode("utf-8")
                        userdata["EncryptTag"] = base64.b64encode(btag).decode("utf-8")
                        userdata["OneTimeVal"] = base64.b64encode(bnonce).decode("utf-8")
                    # Write configure to JSON file
                    try:
                        json.dump(userdata, conffile, indent = 4)
                    except OSError:
                        logger.error("Can't generate configuration file, referring to information below.")
                        raise
                    except Exception:
                        logger.error(UNKNOWNEXMSG)
                        raise
        except OSError:
            logger.error(
                "Can't open configure file \"{}\" for writing, referring to information below.".format(CONFPATH))
            raise
        except Exception:
            logger.error(UNKNOWNEXMSG)
            raise
        except BaseException:
            os.remove(CONFPATH)
            raise
        else:
            break


def encrypt(string: str, passwd: str):
    key = hashlib.shake_256(passwd.encode("utf-8")).hexdigest(8)  # 16-byte key
    crypto = AES.new(key.encode("utf-8"), AES.MODE_EAX)
    bnonce = crypto.nonce
    bcipher, btag = crypto.encrypt_and_digest(string.encode("utf-8"))

    return bcipher, btag, bnonce


def decrypt(bcipher: bytes, passwd: str, btag: bytes, bnonce: bytes):
    key = hashlib.shake_256(passwd.encode("utf-8")).hexdigest(8)
    crypto = AES.new(key.encode("utf-8"), AES.MODE_EAX, nonce = bnonce)
    string = crypto.decrypt(bcipher).decode("utf-8")
    crypto.verify(btag)

    return string


def APIreq(req: str, userdata = None, method: str = "GET", data: bytes = b""):
    logger = logging.getLogger(__name__)
    logger.debug("Logger initialized.")

    headers = {}
    response = None

    if userdata:
        headers["Content-Type"] = "application/json"
        if userdata["GlobalAPIMode"]:
            logger.debug("Global API mode enabled.")
            headers["X-Auth-Email"] = userdata["E-mail"]
            headers["X-Auth-Key"] = userdata["APIKey"]
        else:
            headers["Authorization"] = "Bearer " + userdata["APIKey"]

    # HTTP/GET request
    try:
        logger.debug("Sending request to server...")
        req = urllib.request.Request(req, data, headers, method = method)
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        logger.error(e)
        try:
            raise HTTPErrors.HTTPErrorMap[e.code](e.url, e.code, e.msg, e.hdrs, e.fp)
        except KeyError:
            if e.code // 100 == 1 or e.code // 100 == 2 or e.code // 100 == 3:
                pass
            elif e.code // 100 == 4:
                raise HTTPErrors.ClientError(e.url, e.code, e.msg, e.hdrs, e.fp)
            elif e.code // 100 == 5:
                raise HTTPErrors.ServerError(e.url, e.code, e.msg, e.hdrs, e.fp)
            else:
                raise
    except urllib.error.URLError as e:
        logger.error("Request failed. Please check Internet connection. Reason:")
        logger.error(e)
        raise
    except Exception:
        logger.error(UNKNOWNEXMSG)
        raise

    return response


def printconf(userdata: dict):
    for i in ["{}: {}".format(k, userdata[k]) for k in userdata.keys()]:
        print(i)


if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO,
                        format = "[%(asctime)s] %(name)s: %(funcName)s(): [%(levelname)s] %(message)s")
    _logger = logging.getLogger(__name__)
    _logger.debug("Logger initialized.")

    while True:
        try:
            main()
        except Restart:
            _logger.info("Restarting into program entry point...")
        except MException as _e:
            print()
            _logger.error("*********************************")
            _logger.error("An fatal exception has occurred:")
            for _line in traceback.format_exc().splitlines():
                _logger.error(_line)
            _logger.error("")
            _logger.error("Additional information:")
            for _line in _e.errormsg().splitlines():
                _logger.error(_line)
            _logger.error("")
            _logger.error("Program exits abnormally.")
            _logger.error("*********************************")
            break
        except Exception as _e:
            print()
            _logger.error("*********************************")
            _logger.error("An fatal exception has occurred:")
            for _line in traceback.format_exc().splitlines():
                _logger.error(_line)
            # _logger.error(re.search(r"<class '(.+)'>", str(_e.__class__)).group(1) + ": " + str(_e) + "\n")
            _logger.error("")
            _logger.error("Program exits abnormally.")
            _logger.error("*********************************")
            break
        except BaseException as _e:
            print()
            _logger.error("==============================")
            _logger.error("Program was terminated due to:\n")
            _logger.error(re.search(r"<class '(.+)'>", str(_e.__class__)).group(1) + "\n")
            _logger.error("==============================")
            break
        else:
            break
