import pssst

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def test_round_trip():
    server_private_key = X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

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
    server_private_key = X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()

    client_private_key = X25519PrivateKey.generate()
    client_public_key = client_private_key.public_key()
    
    client = pssst.PSSSTClient(server_public_key, client_private_key)
    server = pssst.PSSSTServer(server_private_key)

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, received_client_public_key, server_reply_handler = server.unpack_request(request_packet)

    assert received_message == test_message
    
    source_client_key_bytes = client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    received_client_key_bytes = received_client_public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    
    assert received_client_key_bytes == source_client_key_bytes

    reply_packet = server_reply_handler(received_message)
    round_trip_message = client_reply_handler(reply_packet)

    assert round_trip_message == test_message
