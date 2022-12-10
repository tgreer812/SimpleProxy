
'''This module creates a HookedReverseProxy and HookedProxy

Generically speaking, a hooked proxy is a proxy that allows the user
to attach callback functions that are able to modify requests and responses
in transit.

TODO: modify class method names to conform to pep
TODO: figure out if the architecture of the Hook should be modified. Is it too long? Anything that can be decoupled?
TODO: do this with more sleep :)
'''

from twisted.web.proxy import ReverseProxy, ReverseProxyRequest


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

    def __init__(self, handleRequest=None, handleResponse=None):
        """Initialize a Hook object.

        Args:
            handleRequest: A function that takes the method, host, path, headers, body, and version of a request as
                           arguments and returns a tuple of these values. This function will be called when a request
                           is received by the Hook.
            handleResponse: A function that takes the status, headers, and body of a response as arguments and returns a
                            tuple of these values. This function will be called when a response is received by the Hook.
        """
        self.handleRequest = handleRequest
        self.handleResponse = handleResponse
        self.state = {
            'active': True
        }
        self.callbacks = {
            'deactivateHook': self.deactivateHook,
            'activateHook': self.activateHook,
            'setState': self.setState,
            'isActive': self.isActive
        }
    
    class InvalidHookStateError(Exception):
        """Raised when the input provided by the user is invalid."""

    class InvalidHookCallbackReturnType(Exception):
        """Raised when the return type of a hook is invalid."""

    def _check_callback_return_type(self, result, expected_return_type):
        """Checks that the given result is of the expected return type.

        Args:
            result: The result to check.
            expected_return_type: The expected return type of the result.

        Raises:
            InvalidHookCallbackReturnType: If the result is not of the expected return type.
        """
        if not isinstance(result, expected_return_type):
            raise self.InvalidHookCallbackReturnType(f'The result must be of type {expected_return_type}.')
    
    def _validate_request_callback_return_type(self, result):
        self.check_callback_return_type(result, tuple)
        if len(result) != 6:
            raise self.InvalidHookCallbackReturnType('The handleRequest callback must return a tuple containing bytes method, bytes host, bytes path, dict headers, bytes body, and bytes version.')
        self.check_callback_return_type(result[0], bytes)
        self.check_callback_return_type(result[1], bytes)
        self.check_callback_return_type(result[2], bytes)
        self.check_callback_return_type(result[3], dict)
        self.check_callback_return_type(result[4], bytes)
        self.check_callback_return_type(result[5], bytes)
    
    def _validate_response_callback_return_type(self, result):
        if not isinstance(result, tuple) or len(result) != 3:
            raise self.InvalidHookCallbackReturnType('The handleResponse callback must return a tuple containing a bytes status, dict headers, and bytes body.')
        if not isinstance(result[0], bytes):
            raise self.InvalidHookCallbackReturnType('The status returned by the handleResponse callback must be of type bytes.')
        if not isinstance(result[1], dict):
            raise self.InvalidHookCallbackReturnType('The headers returned by the handleResponse callback must be of type dict.')
        if not isinstance(result[2], bytes):
            raise self.InvalidHookCallbackReturnType('The body returned by the handleResponse callback must be of type bytes.')

    def isActive(self):
        return self.state['active']

    def setState(self, newState: dict):
        """Set the internal state of the Hook object.

        Args:
            newState: The new internal state of the Hook object (dict).

        Raises:
            InvalidInputError: If the newState provided by the user is invalid.
        """

        # Check if the input provided by the user is valid
        if not isinstance(newState, dict):
            raise self.InvalidHookStateError("The new state must be a dict object.")
        if 'active' not in newState:
            raise self.InvalidHookStateError("The new state must contain a key named 'active'.")
            
        # Set the new internal state of the Hook object
        self.state = newState

    def deactivateHook(self):
        self.state['active'] = False
    
    def activateHook(self):
        self.state['active'] = True
    
    def onRequestReceived(self, method: bytes, host: bytes, path: bytes, headers: dict, body: bytes=b"" , version: bytes=b"HTTP/2"):
        """Run the user-defined handleRequest callback and call the handleRequest
        function of the next hook in the chain (if there is one) with the result
        of the previous handleRequest call. If there are no more hooks in the
        chain, return the result of the previous handleRequest call.

        Args:
            method: The HTTP method of the request (bytes).
            host: The host of the request (bytes).
            path: The path of the request (bytes).
            headers: The headers of the request (dict).
            body: The body of the request (bytes).
            version: The HTTP version of the request (bytes).
        
        Raises:
            InvalidHookCallbackReturnType: If the result is not of the expected return type.

        Returns:
            The result of the handleRequest call.
        """
        # Check if the hook is active
        if not self.state['active']:
            return method, host, path, headers, body, version
        
        # Call the user-defined handleRequest callback
        if (self.handleRequest is not None):
            # Ensure that the handleRequest callback returns the relevant types
            result = self.handleRequest(
                method,
                host,
                path,
                headers,
                body,
                version,
                self.callbacks
            )
            self._validate_request_callback_return_type(result)
            return result

        return method, host, path, headers, body, version

    def onResponseReceived(self, status: bytes, headers: dict, body: bytes):
        """Run the user-defined handleResponse callback and call the handleResponse
        function of the next hook in the chain (if there is one) with the result
        of the previous handleResponse call. If there are no more hooks in the
        chain, return the result of the previous handleResponse call.

        Args:
            status: The status code of the response (bytes).
            headers: The headers of the response (dict).
            body: The body of the response (bytes).

        Raises:
            InvalidHookCallbackReturnType: If the result is not of the expected return type.

        Returns:
            The result of the handleResponse call.
        """
        # Check if the hook is active
        if not self.state['active']:
            return status, headers, body
        
        # Call the user-defined handleResponse callback
        if (self.handleResponse is not None):
            # Ensure that the handleResponse callback returns a bytes status, dict headers, and bytes body
            result = self.handleResponse(
                status,
                headers,
                body,
                self.callbacks
            )
            self._validate_response_callback_return_type(result)
            return result

        return status, headers, body

    
class HookChain:
    """A chain of Hook objects that can be used to intercept and modify requests and responses.
    """

    def __init__(self):
        """Initialize a HookChain object.
        """
        self.hooks = []
        self.last_hook = None

    def registerHook(self, hook: Hook):
        """Add a Hook object to the end of the chain.

        Args:
            hook: The Hook object to add to the chain.

        Returns:
            The HookChain object (for method chaining).
        """
        #TODO: validate that hook is of type Hook
        self.hooks.append(hook)

    def onRequestReceived(self, method: bytes, host: bytes, path: bytes, headers: dict, callbacks: dict, body: bytes=b"", version: bytes=b"HTTP/2"):
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
            result = hook.onRequestReceived(method, host, path, headers, body, version, callbacks)
        return result

    def onResponseReceived(self, status: bytes, headers: dict, body: bytes, callbacks: dict):
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
            result = hook.onResponseReceived(status, headers, body, callbacks)
        return result


class HookedReverseProxyRequest(ReverseProxyRequest):
    ''' A reverse proxy request for the http protocol
    '''
    hookChain = HookChain()

    def registerHooks(self, hooks):
        self.hookChain.registerHooks(hooks)

    def write(self, data):

        # -------------- REMOVE
        log.info("=====Response=====")
        print(self.responseHeaders)
        #hexdump(data)
        print(data[:10])
        # ------------- ENDREMOVE
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

        clientFactory = self.proxyClientFactoryClass(
            self.method,
            self.uri,
            self.clientproto,
            self.getAllHeaders(),
            self.content.read(),
            self
        )
        self.reactor.connectTCP(self.factory.host, self.factory.port, clientFactory)
        

class HookedReverseProxy(ReverseProxy):
    '''
    Implements a simple hooked reverse proxy
    '''
    requestFactory = HookedReverseProxyRequest
    registeredHooks = []

    def __init__(self):
        self.requestFactory.registerHooks(self.registeredHooks)
        self.super().__init__()


