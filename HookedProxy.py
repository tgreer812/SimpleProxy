
'''This module creates a HookedReverseProxy and HookedProxy

Generically speaking, a hooked proxy is a proxy that allows the user
to attach callback functions that are able to modify requests and responses
in transit.

TODO: modify class method names to conform to pep
'''

from sympy import true
from twisted.web.proxy import ReverseProxy, ReverseProxyRequest, ProxyClientFactory, ProxyClient, ReverseProxyResource
from twisted.web.server import Site
from typing import List


class Hook:
    """A chainable hook that can be used to intercept and modify requests and responses.

    Raises:
        InvalidHookStateError: If the input provided by the user is invalid.

    Instance variables:
        handleRequest: A function that takes the method, host, path, headers, body, and version of a request as
                       arguments and returns a tuple of these values. This function will be called when a request
                       is received by the Hook.
        handleResponse: A function that takes the status, headers, and body of a response as arguments and returns a
                        tuple of these values. This function will be called when a response is received by the Hook.
        next: The next hook in the chain.
        state: A dictionary that can be used to store state between requests and responses.
        active: A boolean describing if the hook is active or not. Inactive hooks will do nothing when executed by the hook chain
        callbacks: A dictionary of functions that can be used to modify the hook directly.
    """

    def __init__(self):
        """Initialize a Hook object.

        Args:
            handleRequest: A function that takes the method, host, path, headers, body, and version of a request as
                           arguments and returns a tuple of these values. This function will be called when a request
                           is received by the Hook.
            handleResponse: A function that takes the status, headers, and body of a response as arguments and returns a
                            tuple of these values. This function will be called when a response is received by the Hook.
        """
        self.active = True
        self.state = {}

    def _check_callback_return_type(self, result, expected_return_type):
        """Checks that the given result is of the expected return type.

        Args:
            result: The result to check.
            expected_return_type: The expected return type of the result.

        Raises:
            InvalidHookCallbackReturnType: If the result is not of the expected return type.
        """
        if not isinstance(result, expected_return_type):
            raise TypeError(f'The result must be of type {expected_return_type}. Got {type(result)}.')
    
    def _validate_request_callback_return_type(self, result):
        self.check_callback_return_type(result, tuple)
        if len(result) != 6:
            raise TypeError('The handleRequest callback must return a tuple containing bytes method, bytes host, bytes path, dict headers, bytes body, and bytes version.')
        self.check_callback_return_type(result[0], bytes)
        self.check_callback_return_type(result[1], bytes)
        self.check_callback_return_type(result[2], bytes)
        self.check_callback_return_type(result[3], dict)
        self.check_callback_return_type(result[4], bytes)
        self.check_callback_return_type(result[5], bytes)

    def _validate_response_callback_return_type(self, result):
        if not isinstance(result, tuple) or len(result) != 3:
            raise TypeError('The handleResponse callback must return a tuple containing a bytes status, dict headers, and bytes body.')
        self.check_callback_return_type(result[0], bytes)
        self.check_callback_return_type(result[1], dict)
        self.check_callback_return_type(result[2], bytes)

    def isActive(self):
        return self.active
        #return self.state['active']

    def setState(self, newState: dict):
        """Set the internal state of the Hook object.

        Args:
            newState: The new internal state of the Hook object (dict).

        Raises:
            InvalidInputError: If the newState provided by the user is invalid.
        """

        # Check if the input provided by the user is valid
        if not isinstance(newState, dict):
            raise TypeError("The new state must be a dict object.")
            
        # Set the new internal state of the Hook object
        self.state = newState

    def deactivateHook(self):
        #TODO: docstrings for all these methods
        self.active = False
    
    def activateHook(self):
        self.active = True
    
    def onRequestReceived(self, method: bytes, host: bytes, path: bytes, headers: dict, body: bytes=b"" , version: bytes=b"HTTP/1"):
        """
        Handles an incoming HTTP request.

        This method is called whenever a new request is received by the server. It checks to make sure
        the hook is active. If so it calls the onHandleRequest method for
        modification of a request before it is processed by the server. 

        Args:
            method: The HTTP method of the request (e.g. GET, POST, PUT, etc.)
            host: The hostname of the server.
            path: The path of the requested resource on the server.
            headers: A dictionary of headers sent with the request.
            body: The body of the request.
            version: The HTTP version of the request (e.g. HTTP/1.1 or HTTP/2).

        Returns:
            A tuple containing the modified request parameters. The tuple should be in the following
            format: (method, host, path, headers, body, version)
        """
        # Check if the hook is active
        if not self.active:
            return method, host, path, headers, body, version

        # Allow the user to override the handleRequest method
        new_method,     \
        new_host,       \
        new_path,       \
        new_headers,    \
        new_body,       \
        new_version = self.onHandleRequest(method, host, path, headers, body, version)
        self._validate_request_callback_return_type(
            (new_method, new_host, new_path, new_headers, new_body, new_version)
        )
        
        return new_method, new_host, new_path, new_headers, new_body, new_version

    def onResponseReceived(self, status: bytes, headers: dict, body: bytes):
        """
        Handles an incoming HTTP response.

        This method is called whenever a response is received by the client. It allows the user to
        modify the response before it is processed by the client.

        Args:
            status: The status code of the response (e.g. 200 for success, 404 for not found, etc.)
            headers: A dictionary of headers sent with the response.
            body: The body of the response.

        Returns:
            A tuple containing the modified response parameters. The tuple should be in the following
            format: (status, headers, body)
        """
        # Check if the hook is active
        if not self.active:
            return status, headers, body

        # Allow the user to override the handleResponse method
        new_status, new_headers, new_body = self.onHandleResponse(status, headers, body)
        self._validate_response_callback_return_type((new_status, new_headers, new_body))

        return new_status, new_headers, new_body

    def onHandleRequest(self, method: bytes, host: bytes, path: bytes, headers: dict, body: bytes=b"" , version: bytes=b"HTTP/1"):
        """
        Handles an incoming HTTP request.

        This method is called by the `onRequestReceived` method whenever a new request is received by
        the server. It allows the user to specify custom behavior for handling requests. This method
        must be overridden by a user-defined subclass.

        Args:
            method: The HTTP method of the request (e.g. GET, POST, PUT, etc.)
            host: The hostname of the server.
            path: The path of the requested resource on the server.
            headers: A dictionary of headers sent with the request.
            body: The body of the request.
            version: The HTTP version of the request (e.g. HTTP/1.1 or HTTP/2).

        Returns:
            A tuple containing the modified request parameters. The tuple should be in the following
            format: (method, host, path, headers, body, version)
        """
        # This method must be overridden by a user-defined subclass
        raise NotImplementedError('onHandleRequest() must be overridden by a user-defined subclass')

    def onHandleResponse(self, status: bytes, headers: dict, body: bytes):
        """
        Handles an incoming HTTP response.

        This method is called by the `onResponseReceived` method whenever a response is received by the
        client. It allows the user to specify custom behavior for handling responses. This method
        must be overridden by a user-defined subclass.

        Args:
            status: The status code of the response (e.g. 200 for success, 404 for not found, etc.)
            headers: A dictionary of headers sent with the response.
            body: The body of the response.

        Returns:
            A tuple containing the modified response parameters. The tuple should be in the following
            format: (status, headers, body)
        """
        # This method must be overridden by a user-defined subclass
        raise NotImplementedError('onHandleResponse() must be overridden by a user-defined subclass')
    
    
class HookChain:
    """A chain of Hook objects that can be used to intercept and modify requests and responses.
    """

    def __init__(self):
        """Initialize a HookChain object.
        """
        self.hooks = []

    def getHooks(self):
        return self.hooks

    def registerHooks(self, hooks: List[Hook]):
        for hook in hooks:
            self.registerHook(hook)

    def registerHook(self, hook: Hook):
        """Add a Hook object to the end of the chain.

        Args:
            hook: The Hook object to add to the chain.

        Returns:
            The HookChain object (for method chaining).
        """
        if not isinstance(hook, Hook):
            raise TypeError(f'\'hook\' must be of type Hook. Got {type(hook)}')
        self.hooks.append(hook)

    def onRequestReceived(self, method: bytes, host: bytes, path: bytes, headers: dict, body: bytes=b"", version: bytes=b"HTTP/2"):
        """Run the onRequestReceived method of each Hook in the chain, starting with the first Hook.

        Args:
            method: The HTTP method of the request (bytes).
            host: The host of the request (bytes).
            path: The path of the request (bytes).
            headers: The headers of the request (dict).
            body: The body of the request (bytes).
            version: The version of the request (bytes).

        Returns:
            The result of the last onRequestReceived method call in the chain.
        """
        result = None
        for hook in self.hooks:
            result = hook.onHandleRequest(method, host, path, headers, body, version)
        return result

    def onResponseReceived(self, status: bytes, headers: dict, body: bytes):
        """Run the onResponseReceived method of each Hook in the chain, starting with the first Hook.

        Args:
            status: The status code of the response (bytes).
            headers: The headers of the response (dict).
            body: The body of the response (bytes).

        Returns:
            The result of the last onResponseReceived method call in the chain.
        """
        result = None
        for hook in self.hooks:
            result = hook.onHandleResponse(status, headers, body)
        return result


class HookedProxyClient(ProxyClient):
    _response_version = b''
    _response_code = b''
    _response_reason = b''
    _response_headers = {}
    _response_data_buffer = b''
    hookChain = HookChain()

    @classmethod
    def registerHooks(cls, hooks):
        cls.hookChain.registerHooks(hooks)

    def handleResponsePart(self, data):
        # Buffer data until all has been read
        self._response_data_buffer += data

    def handleResponseEnd(self):
        """
        Write the buffered headers and body to the transport
        Finish the original request, indicating that the response has been
        completely written to it, and disconnect the outgoing transport.
        """
        if self._finished:
            return
        
        self._status = f"{self.father.clientproto.decode()} {self.father.code} {self.father.code_message.decode()}".encode('utf-8')

        # Get all headers and save them temporarily
        for _header, _value in self.father.responseHeaders.getAllRawHeaders():
            assert len(_value) == 1
            # For some reason the Headers class stores the header value in a list - extract it
            self._response_headers[_header] = _value[0]
        
        # Also clear the headers from the father so we can write only the returned ones from the hook back
        # TODO: There is probably a better way of doing this so we don't need two loops, but it's bitching that
        # I'm changing the size of the iterator mid iteration. rip
        for _header, _value in self._response_headers.items():
            self.father.responseHeaders.removeHeader(_header)

        # Apply all hooks
        self.hookChain.onResponseReceived(
            self._status, 
            self._response_headers, 
            self._response_data_buffer
        )

        # Father is the request that created the factory that generated this protocol
        # After applying hook we need to write the headers back to the father's raw headers
        for k,v in self._response_headers.items():
            self.father.responseHeaders.addRawHeader(k, v)

        # This will write the headers and the data buffer back to the original client.
        self.father.write(self._response_data_buffer)

        # Mark it as complete and close the transport
        self._finished = True
        self.father.finish()
        self.transport.loseConnection()
    

class HookedProxyClientFactory(ProxyClientFactory):
    """
    """

    protocol = HookedProxyClient
    hookChain = HookChain()

    def registerHooks(self, hooks):
        self.hookChain.registerHooks(hooks)
        self.protocol.registerHooks(hooks)


class HookedReverseProxyRequest(ReverseProxyRequest):
    ''' This is a request object (encapsulates a request and response)
    '''
    proxyClientFactoryClass = HookedProxyClientFactory
    hookChain = HookChain()

    @classmethod
    def registerHooks(cls, hooks):
        cls.hookChain.registerHooks(hooks)

    def process(self):
        self.hookChain.onRequestReceived(
            self.method,
            self.host.host.encode('utf-8'),
            self.path,
            self.requestHeaders._rawHeaders,
            self.content,
            self.clientproto
        )

        clientFactory = self.proxyClientFactoryClass(
            self.method,
            self.uri,
            self.clientproto,
            self.getAllHeaders(),
            self.content.read(),
            self
        )

        clientFactory.registerHooks(self.hookChain.getHooks())
        print(self.channel.factory.resource.host)
        self.reactor.connectTCP(self.channel.factory.resource.host, self.channel.factory.resource.port, clientFactory)
        

class HookedReverseProxy(ReverseProxy):
    '''
    Implements a simple hooked reverse proxy. This is a protocol.
    '''
    #requestFactory = HookedReverseProxyRequest
    registeredHooks = []

    def __init__(self):
        self.requestFactory.registerHooks(self.registeredHooks)
        self.super().__init__()


class HookedReverseProxyResource(ReverseProxyResource):
    proxyClientFactoryClass = HookedProxyClientFactory


class HookedSite(Site):
    """
    """

    #TODO: Decouple this since we need HookedSite to work for forward and reverse proxies (just pass as a parameter)
    requestFactory = HookedReverseProxyRequest

    # def __init__(self, resource, requestFactory=None, *args, **kwargs):
    #     super().__init__(resource, requestFactory, *args, **kwargs)

    def registerHooks(self, hooks : List[Hook]):
        self.requestFactory.registerHooks(hooks)
    
