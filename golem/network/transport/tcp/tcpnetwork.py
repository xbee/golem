import logging

from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, TCP6ServerEndpoint, \
    TCP6ClientEndpoint

from golem.network.transport.network import Network

logger = logging.getLogger(__name__)


class TCPNetwork(Network):
    def __init__(self, protocol_factory, use_ipv6=False, timeout=5):
        super(TCPNetwork, self).__init__(
            protocol_factory,
            Transport4ServerEndpoint=TCP4ServerEndpoint,
            Transport6ServerEndpoint=TCP6ServerEndpoint,
            Transport4ClientEndpoint=TCP4ClientEndpoint,
            Transport6ClientEndpoint=TCP6ClientEndpoint,
            use_ipv6=use_ipv6,
            timeout=timeout
        )
