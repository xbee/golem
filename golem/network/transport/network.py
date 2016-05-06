import abc
import logging
import re

from ipaddress import AddressValueError, IPv6Address, IPv4Address, ip_address
from twisted.internet.defer import maybeDeferred

from golem.core.variables import MIN_PORT, MAX_PORT

logger = logging.getLogger(__name__)


class AbstractNetwork(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def connect(self, connect_info, **kwargs):
        return

    @abc.abstractmethod
    def listen(self, listen_info, **kwargs):
        return

    @abc.abstractmethod
    def stop_listening(self, listening_info, **kwargs):
        return


class Network(AbstractNetwork):
    def __init__(self, protocol_factory,
                 Transport4ServerEndpoint, Transport6ServerEndpoint,
                 Transport4ClientEndpoint, Transport6ClientEndpoint,
                 use_ipv6=False, timeout=5):
        """
        Network information
        :param ProtocolFactory protocol_factory: Protocols should be at least ServerProtocol implementation
        :param bool use_ipv6: *Default: False* should network use IPv6 server endpoint?
        :param int timeout: *Default: 5*
        :return None:
        """
        self.Transport4ServerEndpoint = Transport4ServerEndpoint
        self.Transport6ServerEndpoint = Transport6ServerEndpoint
        self.Transport4ClientEndpoint = Transport4ClientEndpoint
        self.Transport6ClientEndpoint = Transport6ClientEndpoint

        from twisted.internet import reactor
        self.reactor = reactor
        self.protocol_factory = protocol_factory
        self.use_ipv6 = use_ipv6
        self.timeout = timeout
        self.active_listeners = {}

    def connect(self, connect_info, **kwargs):
        """
        Connect network protocol factory to address from connect_info.
        :param golem.network.transport.network.ConnectInfo connect_info:
        :param kwargs: any additional parameters
        :return None:
        """
        self.__try_to_connect_to_addresses(connect_info.socket_addresses, connect_info.established_callback,
                                           connect_info.failure_callback, **kwargs)

    def listen(self, listen_info, **kwargs):
        """
        Listen with network protocol factory on a  socket specified by listen_info
        :param golem.network.transport.network.PortListenInfo listen_info:
        :param kwargs: any additional parameters
        :return None:
        """
        self.__try_to_listen_on_port(listen_info.port_start, listen_info.port_end, listen_info.established_callback,
                                     listen_info.failure_callback, **kwargs)

    def stop_listening(self, listening_info, **kwargs):
        """
        Stop listening on a socket specified by listening_info
        :param golem.network.transport.network.PortListeningInfo listening_info:
        :param kwargs: any additional parameters
        :return None|Deferred:
        """
        port = listening_info.port
        listening_port = self.active_listeners.get(port)
        if listening_port:
            defer = maybeDeferred(listening_port.stopListening)

            if not defer.called:
                defer.addCallback(self.__stop_listening_success, listening_info.stopped_callback, **kwargs)
                defer.addErrback(self.__stop_listening_failure, listening_info.stopped_errback, **kwargs)
            del self.active_listeners[port]
            return defer
        else:
            logger.warning("Can't stop listening on port {}, wasn't listening.".format(port))
            self.__stop_listening_failure(None, listening_info.stopped_errback, **kwargs)

    def __try_to_connect_to_addresses(self, addresses, established_callback, failure_callback, **kwargs):
        if len(addresses) == 0:
            logger.warning("No addresses for connection given")
            self.__callback(failure_callback, **kwargs)
            return

        address = addresses[0].address
        port = addresses[0].port

        self.__try_to_connect_to_address(address, port,
                                         self.__connection_to_address_established,
                                         self.__connection_to_address_failure,
                                         addresses_to_arg=addresses,
                                         established_callback_to_arg=established_callback,
                                         failure_callback_to_arg=failure_callback,
                                         **kwargs)

    def __try_to_connect_to_address(self, address, port, established_callback, failure_callback, **kwargs):
        logger.debug("Connection to host {}: {}".format(address, port))

        use_ipv6 = False
        try:
            ip = ip_address(address.decode())
            use_ipv6 = ip.version == 6
        except ValueError:
            logger.warning("{} address is invalid".format(address))
        if use_ipv6:
            endpoint = self.Transport6ClientEndpoint(self.reactor, address, port, self.timeout)
        else:
            endpoint = self.Transport4ClientEndpoint(self.reactor, address, port, self.timeout)

        defer = endpoint.connect(self.protocol_factory)

        defer.addCallback(self.__connection_established, established_callback, **kwargs)
        defer.addErrback(self.__connection_failure, failure_callback, **kwargs)

    def __connection_established(self, conn, established_callback, **kwargs):
        pp = conn.transport.getPeer()
        logger.debug("Connection established {} {}".format(pp.host, pp.port))
        self.__callback(established_callback, conn.session, **kwargs)

    def __connection_failure(self, err_desc, failure_callback, **kwargs):
        logger.info("Connection failure. {}".format(err_desc))
        self.__callback(failure_callback, **kwargs)

    def __connection_to_address_established(self, conn, **kwargs):
        established_callback = kwargs.pop("established_callback_to_arg", None)
        kwargs.pop("failure_callback_to_arg", None)
        kwargs.pop("addresses_to_arg", None)
        self.__callback(established_callback, conn, **kwargs)

    def __connection_to_address_failure(self, **kwargs):
        established_callback = kwargs.pop("established_callback_to_arg", None)
        failure_callback = kwargs.pop("failure_callback_to_arg", None)
        addresses = kwargs.pop("addresses_to_arg", [])
        if len(addresses) > 1:
            self.__try_to_connect_to_addresses(addresses[1:], established_callback, failure_callback, **kwargs)
        else:
            self.__callback(failure_callback, **kwargs)

    def __try_to_listen_on_port(self, port, max_port, established_callback, failure_callback, **kwargs):
        if self.use_ipv6:
            ep = self.Transport6ServerEndpoint(self.reactor, port)
        else:
            ep = self.Transport4ServerEndpoint(self.reactor, port)

        defer = ep.listen(self.protocol_factory)

        defer.addCallback(self.__listening_established, established_callback, **kwargs)
        defer.addErrback(self.__listening_failure, port, max_port, established_callback, failure_callback, **kwargs)

    def __listening_established(self, listening_port, established_callback, **kwargs):
        port = listening_port.getHost().port
        self.active_listeners[port] = listening_port
        self.__callback(established_callback, port, **kwargs)

    def __listening_failure(self, err_desc, port, max_port, established_callback, failure_callback, **kwargs):
        err = err_desc.value.message
        if port < max_port:
            port += 1
            self.__try_to_listen_on_port(port, max_port, established_callback, failure_callback, **kwargs)
        else:
            logger.debug("Can't listen on port {}: {}".format(port, err))
            self.__callback(failure_callback, **kwargs)

    @classmethod
    def __stop_listening_success(cls, result, callback, **kwargs):
        if result:
            logger.info("Stop listening result {}".format(result))
        cls.__callback(callback, **kwargs)

    @classmethod
    def __stop_listening_failure(cls, fail, errback, **kwargs):
        logger.error("Can't stop listening {}".format(fail))
        cls.__callback(errback, **kwargs)

    @staticmethod
    def __callback(function, *args, **kwargs):
        if function:
            function(*args, **kwargs)


class SocketAddress(object):
    """Socket address (host and port)"""

    _dns_label_pattern = re.compile('(?!-)[a-z\d-]{1,63}(?<!-)\Z', re.IGNORECASE)
    _all_numeric_pattern = re.compile('[0-9\.]+\Z')

    def __init__(self, address, port):
        """Creates and validates SocketAddress. Raises
        AddressValueError if 'address' or 'port' is invalid.
        :param str address: IPv4/IPv6 address or hostname
        :param int port:
        """
        self.address = address
        self.port = port
        self.ipv6 = False
        try:
            self.__validate()
        except ValueError, err:
            raise AddressValueError(err.message)

    def __validate(self):
        if type(self.address) is unicode:
            self.address = self.address.encode()
        if type(self.address) is not str:
            raise TypeError('Address must be a string, not a ' +
                            type(self.address).__name__)
        if type(self.port) is not int and type(self.port) is not long:
            raise TypeError('Port must be an int, not a ' +
                            type(self.port).__name__)

        if self.address.find(':') != -1:
            # IPv6 address
            IPv6Address(self.address.decode('utf8'))
            self.ipv6 = True
        else:
            # If it's all digits then guess it's an IPv4 address
            if self._all_numeric_pattern.match(self.address):
                IPv4Address(self.address.decode('utf8'))
            else:
                SocketAddress.validate_hostname(self.address)

        if not (MIN_PORT <= self.port <= MAX_PORT):
            raise ValueError('Port out of range ({} .. {}): {}'.format(
                MIN_PORT, MAX_PORT, self.port))

    def __eq__(self, other):
        return self.address == other.address and self.port == other.port

    def __str__(self):
        return self.address + ":" + str(self.port)

    @staticmethod
    def validate_hostname(hostname):
        """Checks that the given string is a valid hostname.
        See RFC 1123, page 13, and here:
        http://stackoverflow.com/questions/2532053/validate-a-hostname-string.
        Raises ValueError if the argument is not a valid hostname.
        :param str hostname:
        :returns None
        """
        if type(hostname) is unicode:
            hostname = hostname.encode()

        if type(hostname) is not str:
            raise TypeError('Expected string argument, not ' +
                            type(hostname).__name__)

        if hostname == '':
            raise ValueError('Empty host name')
        if len(hostname) > 255:
            raise ValueError('Host name exceeds 255 chars: ' + hostname)
        # Trailing '.' is allowed!
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        segments = hostname.split('.')
        if not all(SocketAddress._dns_label_pattern.match(s) for s in segments):
            raise ValueError('Invalid host name: ' + hostname)

    @staticmethod
    def parse(string):
        """Parses a string representation of a socket address.
        IPv4 syntax: <IPv4 address> ':' <port>
        IPv6 syntax: '[' <IPv6 address> ']' ':' <port>
        DNS syntax:  <hostname> ':' <port>
        Raises AddressValueError if the input cannot be parsed.
        :param str string:
        :returns parsed SocketAddress
        :rtype SocketAddress
        """
        if type(string) is unicode:
            string = string.encode()

        if type(string) is not str:
            raise TypeError('Expected string argument, not ' +
                            type(string).__name__)

        try:
            if string.startswith('['):
                # We expect '[<ip6 addr>]:<portnum>',
                # use ipaddress to parse IPv6 address:
                addr_str, port_str = string.split(']:')
                addr_str = addr_str[1:]
            else:
                # We expect '<ip4 addr or hostname>:<port>'.
                addr_str, port_str = string.split(':')
            port = int(port_str)
        except ValueError:
            raise AddressValueError('Invalid address: port missing or invalid')

        return SocketAddress(addr_str, port)


class PortListeningInfo(object):
    def __init__(self, port, stopped_callback=None, stopped_errback=None):
        """
        Listening port information
        :param int port: port opened for listening
        :param fun|None stopped_callback: *Default: None* deferred callback after listening on this port is stopped
        :param fun|None stopped_errback: *Default: None* deferred callback after stop listening is failure
        :return:
        """
        self.port = port
        self.stopped_callback = stopped_callback
        self.stopped_errback = stopped_errback

    def __str__(self):
        return "A listening port {} information".format(self.port)


class PortListenInfo(object):
    def __init__(self, port_start, port_end=None, established_callback=None, failure_callback=None):
        """
        Information needed for listen function. Network will try to start listening on port_start, then iterate
         by 1 to port_end. If port_end is None, than network will only try to listen on port_start.
        :param int port_start: try to start listening from that port
        :param int port_end: *Default: None* highest port that network will try to listen on
        :param fun|None established_callback: *Default: None* deferred callback after listening established
        :param fun|None failure_callback: *Default: None* deferred callback after listening failure
        :return:
        """
        self.port_start = port_start
        self.port_end = port_end or port_start
        self.established_callback = established_callback
        self.failure_callback = failure_callback

    def __str__(self):
        return "Port listen info: range [{}:{}], callback: {}, errback: {}" \
               .format(self.port_start, self.port_end, self.established_callback, self.failure_callback)


class ConnectInfo(object):
    def __init__(self, socket_addresses,  established_callback=None, failure_callback=None):
        """
        Information for connect function
        :param list socket_addresses: list of SocketAddresses
        :param fun|None established_callback:
        :param fun|None failure_callback:
        :return None:
        """
        self.socket_addresses = socket_addresses
        self.established_callback = established_callback
        self.failure_callback = failure_callback

    def __str__(self):
        return "Connection information: addresses {}, callback {}, errback {}" \
               .format(self.socket_addresses, self.established_callback, self.failure_callback)
