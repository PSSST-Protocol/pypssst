from pssst import *
import pytest

import pssst.pssst

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
    )
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


def test_fake_client_auth():
    server_private_key, server_public_key = generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)
    client_private_key, client_public_key = generate_key_pair(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)
    
    server = PSSSTServer(server_private_key)

    test_message = b"This is a test message"
    
    # Build a fake client-auth packet

    header = Header(cipher_suite=CipherSuite.X25519_AESGCM128, reply=False, client_auth=True)

    partial_key_bytes = client_private_key.exchange(server_public_key)
    client_server_pub = X25519PublicKey.from_public_bytes(partial_key_bytes)
    
    temp_priv_key = X25519PrivateKey.generate()
    exchange_dh = temp_priv_key.exchange(client_public_key)
    shared_secret = temp_priv_key.exchange(client_server_pub)
    client_pub_bytes = client_public_key.public_bytes(encoding=Encoding.Raw,
                                                      format=PublicFormat.Raw)
    temp_private_bytes = temp_priv_key.private_bytes(encoding=Encoding.Raw,
                                                     format=PrivateFormat.Raw,
                                                     encryption_algorithm=NoEncryption())
    
    data = client_pub_bytes + temp_private_bytes + test_message
    
    key, nonce_client, nonce_server = pssst.pssst._DKF_SHA384(exchange_dh, shared_secret)

    # Test 1: make sure that our dummy code works
    
    packet = header.packet_bytes + exchange_dh
    cipher = AESGCM(key)
    data = client_pub_bytes + temp_private_bytes + test_message
    packet += cipher.encrypt(nonce_client, data, packet[:4])
    
    server.unpack_request(packet)

    # Test 2: make sure it fails when we pass the wrong public key
    
    packet = header.packet_bytes + exchange_dh
    cipher = AESGCM(key)
    bad_key = b'\xaa' * 32
    data = bad_key + temp_private_bytes + test_message
    packet += cipher.encrypt(nonce_client, data, packet[:4])
    
    with pytest.raises(pssst.PSSSTClientAuthFailed):
        server.unpack_request(packet)

