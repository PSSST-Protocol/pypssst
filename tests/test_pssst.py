import pssst
import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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

def test_load_key_strings():
    k1 = "A5" * 32
    k2 = "B6" * 32
    # Keys can be any string, so this is just a smoke test
    client = pssst.PSSSTClient(k1, k2)
    server = pssst.PSSSTServer(k2)

def test_load_key_strings_short():
    k1 = "A5" * 31
    k2 = "B6" * 31
    with pytest.raises(ValueError):
        client = pssst.PSSSTClient(k1, k2)

def test_load_key_strings_long():
    k1 = "A5" * 33
    k2 = "B6" * 33
    with pytest.raises(ValueError):
        client = pssst.PSSSTClient(k1, k2)
