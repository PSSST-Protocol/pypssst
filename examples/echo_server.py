#!/usr/bin/env python
import socket
from contextlib import closing

import pssst

import click

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@click.command()
@click.option('-k', '--key-file', help="File containing hex encoded private key")
@click.option('-p', '--port', type=int, help="Port on which to listen", default=45678)
def main(key_file, port):    
    if key_file:
        private_key_text = open(key_file).readline().strip()
        private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_text))
    else:
        private_key = X25519PrivateKey.generate()

    print("Server public key: ",
          private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw).hex())

    server_handler = pssst.PSSSTServer(private_key)
        
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as server_socket:
        server_socket.bind(('127.0.0.1', port))
        while True:
            packet, client_addr = server_socket.recvfrom(2048)
            try:
                data, client_key, reply_handler = server_handler.unpack_request(packet)
            
                reply_packet = reply_handler(data)
                server_socket.sendto(reply_packet, client_addr)
            except pssst.PSSSTException as e:
                print("Server Exception: {}".format(e))


if __name__ == "__main__":
    main()
