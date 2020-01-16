#!/usr/bin/python
# -*- coding: utf-8 -*-

r"""
------------------------------------------------------
            Cloudflare DDNS system v2.0
                    by wxx9248

    Licensed under GNU General Public License v3.0
              Copyright 2020 © wxx9248
------------------------------------------------------

This file defines common HTTP errors.

"""

import urllib.error

class ClientError(urllib.error.HTTPError):
    # 4xx
    pass

class BadRequestError(ClientError):
    # 400
    pass

class UnauthorizedError(ClientError):
    # 401
    pass

class ForbiddenError(ClientError):
    # 403
    pass

class NotFoundError(ClientError):
    # 404
    pass

class MethodNotAllowedError(ClientError):
    # 405
    pass

class RequestTimeOutError(ClientError):
    # 408
    pass

class ServerError(urllib.error.HTTPError):
    # 5xx
    pass

class InternalServerError(ServerError):
    # 500
    pass

class NotImplementedError(ServerError):
    # 501
    pass

class BadGatewayError(ServerError):
    # 502
    pass

class ServiceUnavailableError(ServerError):
    # 503
    pass

class GatewayTimeOutError(ServerError):
    # 504
    pass
