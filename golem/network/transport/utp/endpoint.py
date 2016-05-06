from twisted.internet import interfaces, defer
from twisted.internet.endpoints import _WrappingFactory, TCP6ClientEndpoint
from zope.interface import implementer


@implementer(interfaces.IStreamServerEndpoint)
class _UTPServerEndpoint(object):
    """
    A UTP server endpoint interface
    """

    def __init__(self, reactor, port, backlog, interface):
        self._reactor = reactor
        self._port = port
        self._backlog = backlog
        self._interface = interface

    def listen(self, protocolFactory):
        """
        Implement L{IStreamServerEndpoint.listen} to listen on a UDP/uTP
        socket
        """
        return defer.execute(self._reactor.listenUTP,
                             self._port,
                             protocolFactory,
                             interface=self._interface)


class UTP4ServerEndpoint(_UTPServerEndpoint):
    """
    Implements UTP server endpoint with an IPv4 configuration
    """
    def __init__(self, reactor, port, backlog=50, interface=''):
        _UTPServerEndpoint.__init__(self, reactor, port, backlog, interface)


class UTP6ServerEndpoint(_UTPServerEndpoint):
    """
    Implements UTP server endpoint with an IPv6 configuration
    """
    def __init__(self, reactor, port, backlog=50, interface='::'):
        _UTPServerEndpoint.__init__(self, reactor, port, backlog, interface)


@implementer(interfaces.IStreamClientEndpoint)
class UTP4ClientEndpoint(object):
    """
    UTP client endpoint with an IPv4 configuration.
    """

    def __init__(self, reactor, host, port, timeout=30, bindAddress=None):
        self._reactor = reactor
        self._host = host
        self._port = port
        self._timeout = timeout
        self._bindAddress = bindAddress

    def connect(self, protocolFactory):
        """
        Implement L{IStreamClientEndpoint.connect} to connect via UDP/uTP.
        """
        # TODO: implement NAT traversal
        try:
            wf = _WrappingFactory(protocolFactory)
            self._reactor.connectUTP(
                self._host, self._port, wf,
                timeout=self._timeout, bindAddress=self._bindAddress)
            return wf._onConnection
        except:
            return defer.fail()


@implementer(interfaces.IStreamClientEndpoint)
class UTP6ClientEndpoint(TCP6ClientEndpoint):
    """
    UTP client endpoint with an IPv6 configuration.
    """

    def __init__(self, reactor, host, port, timeout=30, bindAddress=None):
        super(UTP6ClientEndpoint, self).__init__(
            reactor, host, port, timeout, bindAddress
        )

    def _resolvedHostConnect(self, resolvedHost, protocolFactory):
        """
        Connect to the server using the resolved hostname.
        """
        try:
            wf = _WrappingFactory(protocolFactory)
            self._reactor.connectUTP(resolvedHost, self._port, wf,
                timeout=self._timeout, bindAddress=self._bindAddress)
            return wf._onConnection
        except:
            return defer.fail()
