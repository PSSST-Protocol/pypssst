import pssst
import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

@pytest.fixture(scope="session")
def keys():
    server_private_key, server_public_key = pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)
    client_private_key, client_public_key = pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)

    return server_private_key, server_public_key, client_private_key, client_public_key

@pytest.fixture(scope="session")
def server(keys):
    server_private_key, server_public_key, client_private_key, client_public_key = keys
    server = pssst.PSSSTServer(server_private_key)

    return server

@pytest.fixture(scope="session")
def client(keys):
    server_private_key, server_public_key, client_private_key, client_public_key = keys
    client = pssst.PSSSTClient(server_public_key, client_private_key)

    return client

@pytest.fixture(scope="session")
def test_message():
    return b"This is a test message"

def test_bad_request_flip_direction(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)

    # Flip the request bit
    request_packet_x = bytearray(request_packet)
    request_packet_x[0] ^= 0x80
    with pytest.raises(pssst.PSSSTNotRequest):
        server.unpack_request(bytes(request_packet_x))

def test_bad_request_cipher_NONE(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)

    # Try cipher suite NONE
    request_packet_x = bytearray(request_packet)
    request_packet_x[3] = 0x00
    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        server.unpack_request(bytes(request_packet_x))

def test_bad_request_cipher_FF(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)

    # Try a bogus cipher suite
    request_packet_x = bytearray(request_packet)
    request_packet_x[3] |= 0xff
    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        server.unpack_request(bytes(request_packet_x))

def test_bad_request_ciphertext(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)

    # Mess with the ciphertext
    request_packet_x = bytearray(request_packet)
    request_packet_x[37] ^= 0xff
    with pytest.raises(pssst.PSSSTDecryptFailed):
        server.unpack_request(bytes(request_packet_x))

def test_bad_reply_flip_direction(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)
    reply_packet = server_reply_handler(received_message)

    # Flip the request bit
    reply_packet_x = bytearray(reply_packet)
    reply_packet_x[0] ^= 0x80
    with pytest.raises(pssst.PSSSTNotReply):
        client_reply_handler(bytes(reply_packet_x))

def test_bad_cipher_NONE(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)
    reply_packet = server_reply_handler(received_message)

    # Try cipher suite NONE
    reply_packet_x = bytearray(reply_packet)
    reply_packet_x[3] = 0x00
    with pytest.raises(pssst.PSSSTReplyMismatch):
        client_reply_handler(bytes(reply_packet_x))

def test_bad_reply_cipher_FF(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)
    reply_packet = server_reply_handler(received_message)

    # Try a bogus cipher suite
    reply_packet_x = bytearray(reply_packet)
    reply_packet_x[3] |= 0xff
    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        client_reply_handler(bytes(reply_packet_x))

def test_bad_reeply_ID(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)
    reply_packet = server_reply_handler(received_message)

    # Mess with the request identifier
    reply_packet_x = bytearray(reply_packet)
    reply_packet_x[4:36] = b'\0xff' * 32
    with pytest.raises(pssst.PSSSTReplyMismatch):
        client_reply_handler(bytes(reply_packet_x))

def test_bad_reply_ciphertext(server, client, test_message):
    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)
    reply_packet = server_reply_handler(received_message)

    # Mess with the ciphertext
    reply_packet_x = bytearray(reply_packet)
    reply_packet_x[37] ^= 0xff
    with pytest.raises(pssst.PSSSTDecryptFailed):
        client_reply_handler(bytes(reply_packet_x))
