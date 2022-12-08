import logging

LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_DEBUG_FORMAT = "[%(threadName)s-%(filename)s-%(funcName)s-%(lineno)s | %(levelname)s] %(message)s"

log = logging.getLogger(__name__)


# Import the required modules
from argparse import ArgumentParser
from twisted.internet import reactor
from twisted.web.proxy import ReverseProxyResource, ProxyClientFactory
from twisted.web.server import Site, Request

from hexdump import hexdump

import json

class HookedProxyClientFactory(ProxyClientFactory):
    def test(self, line):
        pass

class HookedRequest(Request):

    def write(self, data):
        log.info("=====Response=====")
        print(self.responseHeaders)
        #hexdump(data)
        print(data[:10])
        super().write(data)

    def process(self):
        log.info("=====Request=====")
        
        strHeaders = {}
        for header in self.requestHeaders.getAllRawHeaders():
            strHeaders[header[0].decode('utf-8')] = list(
                map(lambda elem: elem.decode('utf-8'), header[1])
            )
        
        #print(strHeaders)
        output = {
            'method' : self.method.decode('utf-8'),
            'uri' : self.uri.decode('utf-8'),
            #'headers' : self.requestHeaders,
            'headers' : strHeaders,
            'data' : str(self.content)
        }
        print(json.dumps(output,indent=2))
        # log.debug(locals())
        # log.debug(dir())
        super().process()


class HookedSite(Site):

    def render(self,request):
        pass



def start_proxy(rhost, rport, rpath, lport):
    print(rhost, rport, rpath, lport)
    # Create a reverse proxy resource
    proxy = ReverseProxyResource(
      rhost,
      rport,
      b""
    )


    # Create a site and add the proxy resource
    site = Site(proxy,requestFactory=HookedRequest)

    # Start the reactor and listen for incoming connections
    reactor.listenTCP(lport, site)
    reactor.run()


def run(args):
    start_proxy(args.rhost, args.rport, args.rpath, args.lport)


class SymbolFormatter(logging.Formatter):
    symbols = ["x", "!", "-", "+", "DBG"]
    
    def format(self, record):
        symbol_record = logging.makeLogRecord(vars(record))
		
        for index, symbol in enumerate(self.symbols):
            if record.levelno >= (len(self.symbols) - index) * 10:
                symbol_record.levelname = symbol
                break
			
        return super(SymbolFormatter, self).format(symbol_record)


def parse_args():
    # Parse the command-line arguments
    parser = ArgumentParser(description="Reverse proxy server")
    parser.add_argument("--rhost", required=True, type=str, help="")
    parser.add_argument("--rport", default=80, type=int, help="")
    parser.add_argument("--lport", default=8080, type=int, help="")
    parser.add_argument("--rpath", default="", type=str, help="")
    parser.add_argument("--logging", type=str, help="Log file")
    parser.add_argument("--debug", action="store_true", help="Enable debug information")
    
    return parser.parse_args()


def log_init(args):
    log.setLevel(logging.DEBUG)
	
    formatter = logging.Formatter(LOG_DEBUG_FORMAT) if args.debug else SymbolFormatter(LOG_FORMAT)
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
    handler.setFormatter(formatter)
    log.addHandler(handler)
	
    if args.logging:
        file_handler = logging.FileHandler(args.logging)
        file_handler.setLevel(logging.DEBUG if args.debug else logging.INFO)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)


def main():
    args = parse_args()
    log_init(args)

    try:
        run(args)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.error("Unknown exception...")
        log.exception(e)


if __name__ == "__main__":
    main()
