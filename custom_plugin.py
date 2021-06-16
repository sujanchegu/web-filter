import logging

from typing import Optional, List, Dict, Any

from ..http.exception import HttpRequestRejected
from ..http.parser import HttpParser
from ..http.codes import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin
from ..common.utils import text_

import re

logger = logging.getLogger(__name__)


class RegexWebFilterPlugin(HttpProxyBasePlugin):
    keyword_pattern = b"(\s+(?:[Ss][Ee][Ll][Ee][Cc][Tt]|[Uu][Pp][Dd][Aa][Tt][Ee]|[Dd][Ee][Ll][Ee][Tt][Ee]|[Ii][Nn][Ss][Ee][Rr][Tt]|[Pp][Rr][Oo][Cc][Ee][Dd][Uu][Rr][Ee]|[Cc][Rr][Ee][Aa][Tt][Ee]|[Aa][Ll][Tt][Ee][Rr]|[Aa][Nn][Aa][Ll][Yy][Zz][Ee]|[Cc][Aa][Ll][Ll]|[Cc][Oo][Mm][Mm][Ii][Tt]|[Dd][Rr][Oo][Pp]|[Gg][Rr][Aa][Nn][Tt]|[Pp][Uu][Rr][Gg][Ee]|[Rr][Ee][Vv][Oo][Kk][Ee]|[Ee]][Xx][Ee][Cc][Uu][Tt][E|[Uu][Nn][Ii][Oo][Nn]|[Ee][Xx][Ee][Cc]|[Ee][Xx][Ee][Cc]\s[Ss][Pp]|[Ee][Xx][Ee][Cc]\s[Xx][Pp]|[Oo][Rr]|[Aa][Nn][Dd]|[Ll][Ii][Kk][Ee])\s+|\s+(?:[Jj][Aa][Vv][Aa][Ss][Cc][Rr][Ii][Pp][Tt]|[Ss][Cc][Rr][Ii][Pp][Tt])\s+)"
    user_agent_pattern = b'(^[a-zA-Z]+/[\d.]+ [a-zA-Z0-9 .\-:_/\[\]\(\),;\+]*$)'
    cookie_pattern = b"^[a-zA-Z0-9/\+=._\-%]+$"
    # secure_text_pattern = b"^(|[a-zA-Z0-9._!?,*;/\- ]+)$" #Should add * ; 

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def reject_request(self, iReason):
        raise HttpRequestRejected(
            status_code = httpStatusCodes.NOT_FOUND,
            headers = {b'Connection' : b'close'},
            reason = f'{iReason}'.encode()
        )


    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        print(f"{request.type=}")
        print(f"{request.state=}")
        print(f"{request.total_size=}")
        print(f"{request.buffer=}")
        print(f"{request.headers=}")
        print(f"{request.body=}")
        print(f"{request.method=}")
        print(f"{request.url=}")
        print(f"{request.code=}")
        print(f"{request.reason=}")
        print(f"{request.version=}")
        print(f"{request.host=}")
        print(f"{request.port=}")
        print(f"{request.path=}")
        print(f"{request.chunk_parser=}")

        ruleNumber = 0

        #UserAgent - UA
        ruleNumber += 1
        hvalue = request.headers[b'user-agent'][1]
        m = re.findall(self.user_agent_pattern, hvalue)
        if(len(m) != 1 or len(m[0]) != len(hvalue)):
            self.reject_request(f"Rule {ruleNumber}: User Agent Pattern Violated")


        #Cookies - Cookies
        ruleNumber += 1
        hvalue = request.headers[b'cookie'][1]
        cookiesList = hvalue.split(b';')
        for cookie in cookiesList:
            cookie = cookie.lstrip()
            m = re.findall(self.cookie_pattern, cookie)
            if(len(m) != 1 or len(m[0]) != len(cookie)):
                self.reject_request(f"Rule {ruleNumber}: Cookie Pattern Violated")


        #Body - Keyword
        ruleNumber += 1
        if(request.headers[b'content-type'][1] == b'text/plain'):
            m = re.findall(self.keyword_pattern, request.body)
            if(m):
                self.reject_request(f"Rule {ruleNumber}: Keyword Pattern Detected")


        # #Body - ST
        # ruleNumber += 1
        # if(request.headers[b'content-type'][1] == b'text/plain'):
        #     m = re.findall(self.secure_text_pattern, request.body)
        #     if(len(m) != 1 or len(m[0]) != len(request.body)):
        #         self.reject_request(f"Rule {ruleNumber}: Secure Text Pattern Violated") 


        # #Headers - ST
        # ruleNumber += 1
        # for hvalue in request.headers.values():
        #     m = re.findall(self.secure_text_pattern, hvalue[1])
        #     if(len(m) != 1 or len(m[0]) != len(hvalue[1])):
        #         print(m, f"{hvalue[1]=}")
        #         self.reject_request(f"Rule {ruleNumber}: Secure Text Pattern Violated")

        return request


    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass


