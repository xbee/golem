import logging

from golem.network.transport.network import Network

logger = logging.getLogger(__name__)


class UTPNetwork(Network):
    def __init__(self, protocol_factory, use_ipv6=False, timeout=5):
        try:
            import utp.pyutp.utp_twisted
        except ImportError:
            raise EnvironmentError("No uTP library found")

        from golem.network.transport.utp.endpoint import \
            UTP4ServerEndpoint, UTP6ServerEndpoint, \
            UTP4ClientEndpoint, UTP6ClientEndpoint

        super(UTPNetwork, self).__init__(
            protocol_factory,
            Transport4ServerEndpoint=UTP4ServerEndpoint,
            Transport6ServerEndpoint=UTP6ServerEndpoint,
            Transport4ClientEndpoint=UTP4ClientEndpoint,
            Transport6ClientEndpoint=UTP6ClientEndpoint,
            use_ipv6=use_ipv6,
            timeout=timeout
        )


NetworkClass = UTPNetwork
