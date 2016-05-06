import logging
import time
from threading import Lock

from twisted.internet.protocol import connectionDone, Factory

from golem.core.databuffer import DataBuffer
from golem.core.variables import LONG_STANDARD_SIZE
from golem.network.transport.message import Message
from golem.network.transport.session import SessionProtocol

logger = logging.getLogger(__name__)


class BasicProtocol(SessionProtocol):
    lock = Lock()

    """ Connection-oriented basic protocol for twisted, support message serialization"""
    def __init__(self):
        self.opened = False
        self.db = DataBuffer()
        SessionProtocol.__init__(self)

    def send_message(self, msg):
        """
        Serialize and send message
        :param Message msg: message to send
        :return bool: return True if message has been send, False if an error has
        """
        if not self.opened:
            logger.error(msg)
            logger.error("Send message failed - connection closed.")
            return False

        msg_to_send = self._prepare_msg_to_send(msg)

        if msg_to_send is None:
            return False

        self.transport.getHandle()
        self.transport.write(msg_to_send)

        return True

    def close(self):
        """
        Close connection, after writing all pending  (flush the write buffer and wait for producer to finish).
        :return None:
        """
        self.transport.loseConnection()

    def close_now(self):
        """
        Close connection ASAP, doesn't flush the write buffer or wait for the producer to finish
        :return:
        """
        self.opened = False
        self.transport.abortConnection()

    # Protocol functions
    def connectionMade(self):
        """Called when new connection is successfully opened"""
        SessionProtocol.connectionMade(self)
        self.opened = True

    def dataReceived(self, data):
        """Called when additional chunk of data is received from another peer"""
        if not self._can_receive():
            return None

        if not self.session:
            logger.warning("No session argument in connection state")
            return None

        self._interpret(data)

    def connectionLost(self, reason=connectionDone):
        """Called when connection is lost (for whatever reason)"""
        self.opened = False
        if self.session:
            self.session.dropped()

        SessionProtocol.connectionLost(self, reason)

    # Protected functions
    def _prepare_msg_to_send(self, msg):
        ser_msg = msg.serialize()

        db = DataBuffer()
        db.append_len_prefixed_string(ser_msg)
        return db.read_all()

    def _can_receive(self):
        return self.opened and isinstance(self.db, DataBuffer)

    def _interpret(self, data):
        with self.lock:
            self.db.append_string(data)
            mess = self._data_to_messages()
            self.db.clear_buffer()

        if mess is None:
            logger.error("Deserialization message failed")
            return None

        for m in mess:
            self.session.interpret(m)

    def _data_to_messages(self):
        return Message.deserialize(self.db)


class ServerProtocol(BasicProtocol):
    """ Basic protocol connected to server instance
    """
    def __init__(self, server):
        """
        :param Server server: server instance
        :return None:
        """
        BasicProtocol.__init__(self)
        self.server = server

    # Protocol functions
    def connectionMade(self):
        """Called when new connection is successfully opened"""
        BasicProtocol.connectionMade(self)
        self.server.new_connection(self.session)

    def _can_receive(self):
        assert self.opened
        assert isinstance(self.db, DataBuffer)

        if not self.session and self.server:
            self.opened = False
            raise Exception('Peer for connection is None')

        return True


class SafeProtocol(ServerProtocol):
    """More advanced version of server protocol, support for serialization, encryption, decryption and signing
    messages """

    def _prepare_msg_to_send(self, msg):
        if self.session is None:
            logger.error("Wrong session, not sending message")
            return None

        msg = self.session.sign(msg)
        if not msg:
            logger.error("Wrong session, not sending message")
            return None
        ser_msg = msg.serialize()
        enc_msg = self.session.encrypt(ser_msg)

        db = DataBuffer()
        db.append_len_prefixed_string(enc_msg)
        return db.read_all()

    def _data_to_messages(self):
        assert isinstance(self.db, DataBuffer)
        msgs = [msg for msg in self.db.get_len_prefixed_string()]
        messages = []
        for msg in msgs:
            dec_msg = self.session.decrypt(msg)
            if dec_msg is None:
                logger.warning("Decryption of message failed")
                return None
            m = Message.deserialize_message(dec_msg)
            if m is None:
                return None
            m.encrypted = dec_msg != msg
            messages.append(m)
        return messages


class FilesProtocol(SafeProtocol):
    """ Connection-oriented protocol for twisted. Allows to send messages (support for message serialization)
    encryption, decryption and signing), files or stream data."""
    def __init__(self, server=None):
        SafeProtocol.__init__(self, server)

        self.stream_mode = False
        self.consumer = None
        self.producer = None

    def clean(self):
        """ Clean the protocol state. Close existing consumers and producers."""
        if self.consumer is not None:
            self.consumer.close()

        if self.producer is not None:
            self.producer.close()

    def close(self):
        """ Close connection, after writing all pending  (flush the write buffer and wait for producer to finish).
        Close file consumer, data consumer or file producer if they are active.
        :return None: """
        self.clean()
        SafeProtocol.close(self)

    def close_now(self):
        """ Close connection ASAP, doesn't flush the write buffer or wait for the producer to finish.
        Close file consumer, data consumer or file producer if they are active. """
        self.opened = False
        self.clean()
        SafeProtocol.close_now(self)

    def _interpret(self, data):
        self.session.last_message_time = time.time()

        if self.stream_mode:
            self._stream_data_received(data)
            return

        SafeProtocol._interpret(self, data)

    def _stream_data_received(self, data):
        assert self.consumer
        if self._check_stream(data):
            self.consumer.dataReceived(data)
        else:
            logger.error("Wrong stream received")
            self.close_now()

    def _check_stream(self, data):
        return len(data) >= LONG_STANDARD_SIZE


class MidAndFilesProtocol(FilesProtocol):
    """ Connection-oriented protocol for twisted. In the Middleman mode pass message to session without
    decrypting or deserializing it. In normal mode allows to send messages (support for message serialization)
    encryption, decryption and signing), files or stream data."""
    def _interpret(self, data):
        if self.session.is_middleman:
            self.session.last_message_time = time.time()
            with self.lock:
                self.db.append_string(data)
                messages = self.db.read_all()
            self.session.interpret(messages)
            with self.lock:
                self.db.clear_buffer()
        else:
            FilesProtocol._interpret(self, data)

    ############################
    def _prepare_msg_to_send(self, msg):
        if self.session.is_middleman:
            return msg
        else:
            return FilesProtocol._prepare_msg_to_send(self, msg)


class ProtocolFactory(Factory):
    def __init__(self, protocol_class, server=None, session_factory=None):
        self.protocol_class = protocol_class
        self.server = server
        self.session_factory = session_factory

    def buildProtocol(self, addr):
        protocol = self.protocol_class(self.server)
        protocol.set_session_factory(self.session_factory)
        return protocol
