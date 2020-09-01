import pssst
import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

k1_priv = 'c8c875ce0883d2af6466ac025d2c221c01b925762fd082efade036ef4abc4d44'
k1_pub  = 'a3bac8ba07413b9e23c7cbf6c92f639a72c8b5bf8ac9f4ab1651779ce15d3b1d'
k2_priv = '70e6a279b4d468688ae14075b40600abb9e88748a0e02de8b4bb61e98e56667f'
k2_pub  = '92b20bbecb05472574bad88fca8ce6fa0433514a9da6a38472e09267fd6d5f41'

def test_round_trip():
    server_private_key, server_public_key = pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)

    client = pssst.PSSSTClient(server_public_key)
    server = pssst.PSSSTServer(server_private_key)

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, client_public_key, server_reply_handler = server.unpack_request(request_packet)

    assert received_message == test_message

    reply_packet = server_reply_handler(received_message)
    round_trip_message = client_reply_handler(reply_packet)

    assert round_trip_message == test_message

def test_round_trip_text_keys():
    client = pssst.PSSSTClient(k1_pub)
    server = pssst.PSSSTServer(k1_priv)

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, client_public_key, server_reply_handler = server.unpack_request(request_packet)

    assert received_message == test_message

    reply_packet = server_reply_handler(received_message)
    round_trip_message = client_reply_handler(reply_packet)

    assert round_trip_message == test_message

def test_round_trip_client_auth():
    server_private_key, server_public_key = pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)
    client_private_key, client_public_key = pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)

    client = pssst.PSSSTClient(server_public_key, client_private_key)
    server = pssst.PSSSTServer(server_private_key)

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)

    assert received_message == test_message, "Message didn't arrive intact"

    source_client_key_bytes = client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    received_client_key_bytes = received_client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    assert received_client_key_bytes == source_client_key_bytes, "Bad client auth"

    reply_packet = server_reply_handler(received_message)
    round_trip_message = client_reply_handler(reply_packet)

    assert round_trip_message == test_message, "Round trip failed"

def test_round_trip_client_auth_text_keys():
    client = pssst.PSSSTClient(k1_pub, k2_priv)
    server = pssst.PSSSTServer(k1_priv)
    client_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(k2_pub))

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)

    assert received_message == test_message, "Message didn't arrive intact"

    source_client_key_bytes = client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    received_client_key_bytes = received_client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    assert received_client_key_bytes == source_client_key_bytes, "Bad client auth"

    reply_packet = server_reply_handler(received_message)
    round_trip_message = client_reply_handler(reply_packet)

    assert round_trip_message == test_message, "Round trip failed"

def test_round_trip_client_auth_bytes_keys():
    client = pssst.PSSSTClient(bytes.fromhex(k1_pub), bytes.fromhex(k2_priv))
    server = pssst.PSSSTServer(bytes.fromhex(k1_priv))
    client_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(k2_pub))

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)

    assert received_message == test_message, "Message didn't arrive intact"

    source_client_key_bytes = client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    received_client_key_bytes = received_client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    assert received_client_key_bytes == source_client_key_bytes, "Bad client auth"

    reply_packet = server_reply_handler(received_message)
    round_trip_message = client_reply_handler(reply_packet)

    assert round_trip_message == test_message, "Round trip failed"

def test_load_key_strings_short():
    with pytest.raises(ValueError):
        client = pssst.PSSSTClient(k1_pub[:-1])

    with pytest.raises(ValueError):
        client = pssst.PSSSTClient(k1_pub, k2_priv[:-1])

    with pytest.raises(ValueError):
        client = pssst.PSSSTServer(k1_priv[:-1])

def test_load_key_strings_long():
    with pytest.raises(ValueError):
        client = pssst.PSSSTClient(k1_pub+'ff')

    with pytest.raises(ValueError):
        client = pssst.PSSSTClient(k1_pub, k2_priv+'ff')

    with pytest.raises(ValueError):
        client = pssst.PSSSTServer(k1_priv+'ff')
