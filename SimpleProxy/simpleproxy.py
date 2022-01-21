import argparse
import logging
import socket
import hexdump
from threading import Thread, Lock

LOG_FORMAT = "[%(levelname)s] %(message)s"
LOG_DEBUG_FORMAT = "[%(threadName)s-%(filename)s-%(funcName)s-%(lineno)s | %(levelname)s] %(message)s"

log = logging.getLogger(__name__)

#global diode buffers
global_internal_forward_buffer = b''
global_internal_backwards_buffer = b''

#global mutexes
global_ifb_mutex = Lock() 
global_ibb_mutex = Lock()

global_socket_timeout = 0.1

class ProxyEndpoint(Thread):

    def __init__(self, endpoint_index):
        super().__init__(group=None)
        self.endpoint_index = endpoint_index
        self.external_send_buf = b''
        self.external_recv_buf = b''

        assert(endpoint_index == 0 or endpoint_index == 1)

    def relay_loop(self):
        global global_internal_forward_buffer
        global global_internal_backwards_buffer

        #acquire mutex for internal buffer read
        if(self.endpoint_index == 0):
            log.debug("Acquired ibb mutex")
            global_ibb_mutex.acquire()
        else:
            log.debug("Acquired ifb mutex")
            global_ifb_mutex.acquire()
        
        try:
            
            if(self.endpoint_index == 0):
                internal_recv_length = len(global_internal_backwards_buffer)
            else:
                internal_recv_length = len(global_internal_forward_buffer)
            
            #if there is anything to read from the internal diodes copy it to the external buffer
            #clear the related internal diode
            if(internal_recv_length):
                if(self.endpoint_index == 0):
                    self.external_send_buf += global_internal_backwards_buffer
                    global_internal_backwards_buffer = b''
                else:
                    self.external_send_buf += global_internal_forward_buffer
                    global_internal_forward_buffer = b''
                
                print(hexdump.hexdump(self.external_send_buf))

        except Exception as e:
            log.exception("Unknown exception in ProxyEndpoint.relay_loop()")
        finally:
            if(self.endpoint_index == 0):
                log.debug("Released ibb mutex")
                global_ibb_mutex.release()
            else:
                log.debug("Released ifb mutex")
                global_ifb_mutex.release()


        #acquire mutex for internal buffer write
        if(self.endpoint_index == 0):
            log.debug("Acquired ifb mutex")
            global_ifb_mutex.acquire()
        else:
            log.debug("Acquired ibb mutex")
            global_ibb_mutex.acquire()
            

        try:

            #if we received data from external party, forward it to the internal diodes
            if(len(self.external_recv_buf)):
                
                if(self.endpoint_index == 0):
                    global_internal_forward_buffer += self.external_recv_buf
                else:
                    global_internal_backwards_buffer += self.external_recv_buf

                #clear external recv buffer
                self.external_recv_buf = b''

        except Exception as e:
            log.debug("Unknown exception in ProxyEndpoint.relay_loop() internal buffer write")
            log.exception(e)
        finally:
            if(self.endpoint_index == 0):
                log.debug("Released ifb mutex")
                global_ifb_mutex.release()
            else:
                log.debug("Released ibb mutex")
                global_ibb_mutex.release()



    def run(self):
        log.debug('Override this!')
        exit()




class ConnectingProxyEndpoint(ProxyEndpoint):

    def __init__(self, endpoint_index, host, port, should_auto_reconnect=True):
        super().__init__(endpoint_index)

        self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #consider wrapping in try except
        self.my_socket.connect((host,port))



    def receive_from(self, socket_fd):
        
        try:
            buffer = b''
            data = 0
            while True:
                data = socket_fd.recv(4096)

                if not data:
                    break
                log.debug("received data")
                buffer += data
        except IOError:
            pass

        log.debug("returning from receive_from()")
        return buffer

    def relay_loop(self):
        super().relay_loop()

        #read bytes from external party
        try:
            self.external_recv_buf += self.receive_from(self.my_socket)

        except socket.timeout:
            log.debug("socket timeout in recv")
        except Exception as e:
            log.debug("Unknown exception in ConnectingProxyEndpoint.relay_loop()")
            log.exception(e)


        #send bytes to external party
        if(len(self.external_send_buf)):
            try:
                self.my_socket.send(self.external_send_buf)
                self.external_send_buf = b''
            except socket.timeout:
                log.debug("socket timeout in send")
            except Exception as e:
                log.debug("Unknown exception in ConnectingProxyEndpoint.relay_loop() send section")
                log.exception(e)

    def run(self):
        while True:
            self.relay_loop()

class ListeningProxyEndpoint(ProxyEndpoint):

    def __init__(self, endpoint_index, host, port):
        pass

    def receive_from(self, socket_fd):
        pass

    def relay_loop(self):
        pass

    def run(self):
        pass


class SimpleProxy():

    def __init__(self, lhost, lport, rhost, rport, proxy_type, should_auto_reconnect=True):

        socket.setdefaulttimeout(global_socket_timeout)
        self.proxy_type = proxy_type
        if(proxy_type & 2):
            self.first_endpoint = ConnectingProxyEndpoint(0, lhost, lport, should_auto_reconnect=should_auto_reconnect)
        else:
            self.first_endpoint = ListeningProxyEndpoint(0, lhost, lport)

        if(proxy_type & 1):
            self.second_endpoint = ConnectingProxyEndpoint(1, rhost, rport, should_auto_reconnect=should_auto_reconnect)
        else:
            self.second_endpoint = ListeningProxyEndpoint(1, rhost, rport)

    def serve_forever(self):
        self.first_endpoint.start()
        self.second_endpoint.start()

        #TODO: add capability to restart connections 



def run(args, **kwargs):

    log.debug("Creating proxy object")

    #TODO: make last argument a cmdline arg
    simple_proxy_instance = SimpleProxy(kwargs["lhost"], kwargs["lport"],kwargs["rhost"], kwargs["rport"], kwargs["proxy_type"], True)

    simple_proxy_instance.serve_forever()
		
class SymbolFormatter(logging.Formatter):
    symbols = ["x", "!", "-", "+", "DBG"]
    
    def format(self, record):
        symbol_record = logging.makeLogRecord(vars(record))
		
        for index, symbol in enumerate(self.symbols):
            if record.levelno >= (len(self.symbols) - index) * 10:
                symbol_record.levelname = symbol
                break
			
        return super(SymbolFormatter, self).format(symbol_record)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--lhost", type=str, default="127.0.0.1", help="Left endpoint host")
    parser.add_argument("--lport", type=int, default=8080, help="Left endpoint port")
    parser.add_argument("--rhost", type=str, default="127.0.0.1", help="Right endpoint host")
    parser.add_argument("--rport", type=int, default=8081, help="Right endpoint port")
    parser.add_argument("--proxy_type", type=int, default=3, help="Bitmask - first bit = left second bit = right. 00 = both listening, 3 = 11 = both connect")
    parser.add_argument("--debug", action="store_true", default=False, help="Show debug information")
    parser.add_argument("--logging", type=str, help="Log file")
    args = parser.parse_args()
    kwargs = vars(args)

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

    try:
        run(args, **kwargs)
    except KeyboardInterrupt:
        log.debug("keyboard interrupt")
    except AssertionError as e:
        log.error(e)
    except Exception as e:
        log.debug("Unknown exception")
        log.exception(e)
		

if __name__ == "__main__":
	main()
