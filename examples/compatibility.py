#!/usr/bin/env python
"""
An automated compatibility test tool for the Python PSSST module
"""

import os
import sys
import pssst

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import click

# Generate two key pairs
# Emit server public key SERVER_KEY:<hex>
# Emit client public key CLIENT_KEY:<hex>

# Generate dummy message
# Emit message plaintext PLAINTEXT:<hex>

# Create server object

# On recipt of SERVER_KEY:
#  Create unauthenticated client for server
#  Create authenticated client for sever
#  Pack dummy message for each client
#  Emit unauthentricated ciphertext REQUEST:<hex>
#  Emit authenticated ciphertext REQUEST_AUTH:<hex>

# On recipt of CLIENT_KEY:
#  Record key

# On recipt of PLAINTEXT:
#  Record value

# On recipet of REQUEST:
#  Decrypt incoming message
#  Check message against posted plaintext
#  Reverse bytes
#  Encrypt reply and emit as REPLY:<hex>

# On recipet of REQUEST_AUTH:
#  Decrypt incoming message
#  Check message against posted plaintext
#  Check public key against record
#  Reverse bytes
#  Encrypt reply and emit as REPLY_AUTH:<hex>

# On recipet of REPLY:
#  Decrypt incoming message
#  Check message against reversed plaintext

# On recipet of REQUEST_AUTH:
#  Decrypt incoming message
#  Check message against reversed plaintext

# Once two replies have been received:
#  Emit DONE:
# (Note the trailing colon there)


SERVER_KEY = "SERVER_KEY"
CLIENT_KEY = "CLIENT_KEY"
PLAINTEXT = "PLAINTEXT"
REQUEST = "REQUEST"
REQUEST_AUTH = "REQUEST_AUTH"
REPLY = "REPLY"
REPLY_AUTH = "REPLY_AUTH"
DONE = "DONE"

def emit_msg(tag, value=None):
    if value is None:
        value = b''
    msg = "{}:{}\n".format(tag, value.hex())
    sys.stdout.write(msg)
    sys.stdout.flush()

def get_msg():
    line = sys.stdin.readline().strip()
    tag, hex_value = line.split(":")
    return tag, bytes.fromhex(hex_value)

@click.command()
@click.option('-s', '--suite', type=int, help="Cipher suite ID", default=1)
def compat_test(suite):
    cipher_suite = pssst.CipherSuite(suite)

    server_priv, server_pub = pssst.generate_key_pair(cipher_suite)
    client_priv, client_pub = pssst.generate_key_pair(cipher_suite)

    s_pub_bytes = server_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    c_pub_bytes = client_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    emit_msg(SERVER_KEY, s_pub_bytes)
    emit_msg(CLIENT_KEY, c_pub_bytes)

    plaintext = os.urandom(64)
    incoming_plaintext = None

    emit_msg(PLAINTEXT, plaintext)
    server = pssst.PSSSTServer(server_priv, cipher_suite=cipher_suite)

    remote_client_key = None
    
    client = None
    auth_client = None

    client_handler = None
    auth_client_handler = None

    replies = 0
    
    while replies < 2:
        tag, value = get_msg()
        if tag == SERVER_KEY:
            client = pssst.PSSSTClient(value, cipher_suite=cipher_suite)
            auth_client = pssst.PSSSTClient(value, client_priv, cipher_suite=cipher_suite)

            packet, client_handler = client.pack_request(plaintext)
            emit_msg(REQUEST, packet)

            packet, auth_client_handler = auth_client.pack_request(plaintext)
            emit_msg(REQUEST_AUTH, packet)
        elif tag == CLIENT_KEY:
            remote_client_key = value
        elif tag == PLAINTEXT:
            incoming_plaintext = value
        elif tag == REQUEST:
            request_msg, auth_key, reply_handler = server.unpack_request(value)
            assert request_msg == incoming_plaintext, "Decrypted plaintext did not match"
            assert auth_key == None, "Auth key provided for non-auth message"
            reply_msg = bytes(reversed(request_msg))
            reply_packet = reply_handler(reply_msg)
            emit_msg(REPLY, reply_packet)
            replies += 1
        elif tag == REQUEST_AUTH:
            request_msg, auth_key, reply_handler = server.unpack_request(value)
            assert request_msg == incoming_plaintext, "Decrypted plaintext did not match (auth)"
            auth_key_bytes = auth_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
            assert auth_key_bytes == remote_client_key, ("Auth key did not match", auth_key, remote_client_key)
            reply_msg = bytes(reversed(request_msg))
            reply_packet = reply_handler(reply_msg)
            emit_msg(REPLY_AUTH, reply_packet)
        elif tag == REPLY:
            reply_msg = client_handler(value)
            assert reply_msg == bytes(reversed(plaintext)), "Reply bytes did not match"
            replies += 1
            if replies == 2:
                emit_msg(DONE)
        elif tag == REPLY_AUTH:
            reply_msg = auth_client_handler(value)
            assert reply_msg == bytes(reversed(plaintext)), "Reply bytes did not match"
            replies += 1
            if replies == 2:
                emit_msg(DONE)
        elif tag == DONE:
            break

if __name__ == "__main__":
    compat_test()
