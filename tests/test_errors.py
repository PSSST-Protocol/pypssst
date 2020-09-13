import pssst
import pytest

def test_unsupported_ciphers():
    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.NONE)

    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        pssst.PSSSTClient(b'\x55'*32, cipher_suite=pssst.CipherSuite.NONE)

    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        pssst.PSSSTServer(b'\x55'*32, cipher_suite=pssst.CipherSuite.NONE)

def test_reply_handler_reuse():
    server_private_key, server_public_key = pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)

    client = pssst.PSSSTClient(server_public_key)
    server = pssst.PSSSTServer(server_private_key)

    test_message = b"This is a test message"

    request_packet, client_reply_handler = client.pack_request(test_message)
    received_message, client_public_key, server_reply_handler = server.unpack_request(request_packet)

    reply_packet = server_reply_handler(received_message)

    with pytest.raises(pssst.PSSSTHandlerReused):
        reply_packet = server_reply_handler(received_message)
    
    round_trip_message = client_reply_handler(reply_packet)

    with pytest.raises(pssst.PSSSTHandlerReused):
        round_trip_message = client_reply_handler(reply_packet)
