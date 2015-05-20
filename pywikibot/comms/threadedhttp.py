# -*- coding: utf-8  -*-
"""Httplib2 threaded cookie layer.

This class extends httplib2, adding support for:
    - Cookies, guarded for cross-site redirects
    - Thread safe ConnectionPool class
    - HttpProcessor thread class
    - HttpRequest object

"""
from __future__ import unicode_literals

# (C) Pywikibot team, 2007-2014
# (C) Httplib 2 team, 2006
# (C) Metaweb Technologies, Inc., 2007
#
# Partially distributed under the MIT license
# Partially distributed under Metaweb Technologies, Incs license
#    which is compatible with the MIT license

__version__ = '$Id$'
__docformat__ = 'epytext'

# standard python libraries
import codecs
import re
import sys

if sys.version_info[0] > 2:
    from http import cookiejar as cookielib
else:
    import cookielib
    from urlparse import urlparse
    from urllib import splittype, splithost, unquote

import pywikibot

from pywikibot.tools import UnicodeMixin

_logger = "comm.threadedhttp"


class HttpRequest(UnicodeMixin):

    """Object wrapper for HTTP requests that need to block origin thread.

    Usage:

    >>> from .http import Queue
    >>> queue = Queue.Queue()
    >>> cookiejar = cookielib.CookieJar()
    >>> connection_pool = ConnectionPool()
    >>> proc = HttpProcessor(queue, cookiejar, connection_pool)
    >>> proc.setDaemon(True)
    >>> proc.start()
    >>> request = HttpRequest('https://hostname.invalid/')
    >>> queue.put(request)
    >>> request.lock.acquire()
    True
    >>> print(type(request.data))
    <class 'httplib2.ServerNotFoundError'>
    >>> print(request.data)
    Unable to find the server at hostname.invalid
    >>> queue.put(None)  # Stop the http processor thread

    C{request.lock.acquire()} will block until the data is available.

    self.data will be either:
    * a tuple of (dict, unicode) if the request was successful
    * an exception
    """

    def __init__(self, uri, method="GET", body=None, headers=None,
                 callbacks=None, charset=None, **kwargs):
        """
        Constructor.

        See C{Http.request} for parameters.
        """
        self.uri = uri
        self.method = method
        self.body = body
        self.headers = headers
        if isinstance(charset, codecs.CodecInfo):
            self.charset = charset.name
        elif charset:
            self.charset = charset
        elif headers and 'accept-charset' in headers:
            self.charset = headers['accept-charset']
        else:
            self.charset = None

        self.callbacks = callbacks

        self.args = [uri, method, body, headers]
        self.kwargs = kwargs

        self._parsed_uri = None
        self._data = None

    @property
    def data(self):
        """Return the requests response tuple."""
        assert(self._data)
        return self._data

    @data.setter
    def data(self, value):
        """Set the requests response and invoke each callback."""
        self._data = value

        if self.callbacks:
            for callback in self.callbacks:
                callback(self)

    @property
    def exception(self):
        """Get the exception raised by httplib2, if any."""
        if isinstance(self.data, Exception):
            return self.data

    @property
    def response_headers(self):
        """Return the response headers."""
        if not self.exception:
            return self.data.headers

    @property
    def raw(self):
        """Return the raw response body."""
        if not self.exception:
            return self.data.content

    @property
    def parsed_uri(self):
        """Return the parsed requested uri."""
        if not self._parsed_uri:
            self._parsed_uri = urlparse(self.uri)
        return self._parsed_uri

    @property
    def hostname(self):
        """Return the host of the request."""
        return self.parsed_uri.netloc

    @property
    def status(self):
        """HTTP response status.

        @rtype: int
        """
        if not self.exception:
            return self.data.status_code

    @property
    def header_encoding(self):
        """Return charset given by the response header."""
        if not hasattr(self, '_header_encoding'):
            pos = self.response_headers['content-type'].find('charset=')
            if pos >= 0:
                pos += len('charset=')
                encoding = self.response_headers['content-type'][pos:]
                self._header_encoding = encoding
            else:
                self._header_encoding = None
        return self._header_encoding

    @property
    def encoding(self):
        """Detect the response encoding."""
        if not hasattr(self, '_encoding'):
            if not self.charset and not self.header_encoding:
                pywikibot.log(u"Http response doesn't contain a charset.")
                charset = 'latin1'
            else:
                charset = self.charset
            if (self.header_encoding and codecs.lookup(self.header_encoding) !=
                    (codecs.lookup(charset) if charset else None)):
                if charset:
                    pywikibot.warning(u'Encoding "{0}" requested but "{1}" '
                                       'received in the header.'.format(
                        charset, self.header_encoding))
                try:
                    # TODO: Buffer decoded content, weakref does remove it too
                    #       early (directly after this method)
                    self.raw.decode(self.header_encoding)
                except UnicodeError as e:
                    self._encoding = e
                else:
                    self._encoding = self.header_encoding
            else:
                self._encoding = None

            if charset and (isinstance(self._encoding, Exception) or
                            not self._encoding):
                try:
                    self.raw.decode(charset)
                except UnicodeError as e:
                    self._encoding = e
                else:
                    self._encoding = charset

        if isinstance(self._encoding, Exception):
            raise self._encoding
        return self._encoding

    def decode(self, encoding, errors='strict'):
        """Return the decoded response."""
        return self.raw.decode(encoding, errors)

    @property
    def content(self):
        """Return the response decoded by the detected encoding."""
        return self.decode(self.encoding)

    def __unicode__(self):
        """Return the response decoded by the detected encoding."""
        return self.content

    def __bytes__(self):
        """Return the undecoded response."""
        return self.raw


def http_process(session, http_request):
    method = http_request.method
    uri = http_request.uri
    body = http_request.body
    headers = http_request.headers

    try:
        request = session.request(method, uri, data=body, headers=headers)
    except Exception as e:
        http_request.data = e
    else:
        http_request.data = request


# Metaweb Technologies, Inc. License:
#
# ========================================================================
# The following dummy classes are:
# ========================================================================
# Copyright (c) 2007, Metaweb Technologies, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY METAWEB TECHNOLOGIES AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL METAWEB
# TECHNOLOGIES OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ========================================================================

class DummyRequest(object):

    """Simulated urllib2.Request object for httplib2.

    Implements only what's necessary for cookielib.CookieJar to work.
    """

    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers
        self.origin_req_host = cookielib.request_host(self)
        self.type, r = splittype(url)
        self.host, r = splithost(r)
        if self.host:
            self.host = unquote(self.host)

    def get_full_url(self):
        return self.url

    def get_origin_req_host(self):
        # TODO to match urllib2 this should be different for redirects
        return self.origin_req_host

    def get_type(self):
        return self.type

    def get_host(self):
        return self.host

    def get_header(self, key, default=None):
        return self.headers.get(key.lower(), default)

    def has_header(self, key):
        return key in self.headers

    def add_unredirected_header(self, key, val):
        # TODO this header should not be sent on redirect
        self.headers[key.lower()] = val

    def is_unverifiable(self):
        # TODO to match urllib2, this should be set to True when the
        #  request is the result of a redirect
        return False

    unverifiable = property(is_unverifiable)


class DummyResponse(object):

    """Simulated urllib2.Request object for httplib2.

    Implements only what's necessary for cookielib.CookieJar to work.
    """

    def __init__(self, response):
        self.response = response

    def info(self):
        return DummyMessage(self.response)


class DummyMessage(object):

    """Simulated mimetools.Message object for httplib2.

    Implements only what's necessary for cookielib.CookieJar to work.
    """

    def __init__(self, response):
        self.response = response

    def getheaders(self, k):
        k = k.lower()
        self.response.get(k.lower(), None)
        if k not in self.response:
            return []
        # return self.response[k].split(re.compile(',\\s*'))

        # httplib2 joins multiple values for the same header
        #  using ','.  but the netscape cookie format uses ','
        #  as part of the expires= date format.  so we have
        #  to split carefully here - header.split(',') won't do it.
        HEADERVAL = re.compile(r'\s*(([^,]|(,\s*\d))+)')
        return [h[0] for h in HEADERVAL.findall(self.response[k])]

    def get_all(self, k, failobj=None):
        rv = self.getheaders(k)
        if not rv:
            return failobj
        return rv
