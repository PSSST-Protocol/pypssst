#!/usr/bin/env python
import time
import socket
from contextlib import closing
from threading import Thread

import pssst

import click

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


@click.command()
@click.option('-k', '--public_key', required=True, help="Hex-encoded public key")
@click.option('-K', '--client-key-file', help="File containing hex encoded private key")
@click.option('-p', '--port', type=int, help="Port on which to listen", default=45678)
@click.option('-i', '--iterations', type=int, help="Number of requests to send", default=1)
@click.option('-P', '--payload', help="Body to be included in echo request", default="EchoTest")
@click.option('-t', '--threads', type=int, help="Number of parallel threads to run in client", default=1)
def main(public_key, client_key_file, port, iterations, payload, threads):
    if client_key_file:
        private_key_text = open(client_key_file).readline().strip()
        private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_text))
    else:
        private_key = None

    client = pssst.PSSSTClient(public_key, private_key)

    payload = payload.encode("UTF8")
    result_list = []

    tests = [client.pack_request(payload) for _ in range(iterations)]
    
    def send_tests(test_subset):
        replies = 0
        start_time = time.time()
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client_socket:
            client_socket.settimeout(0.25)
            for packet, reply_handler in test_subset:
                client_socket.sendto(packet, ('127.0.0.1', port))
                try:
                    client_socket.recvfrom(2048)
                    replies += 1
                except socket.timeout:
                    pass
        end_time = time.time()
        result_list.append((len(test_subset), replies, end_time - start_time))

    chops = [(iterations * i)//threads for i in range(threads+1)]
    thread_list = [Thread(target=send_tests, args=(tests[chops[i]:chops[i+1]],)) for i in range(threads)]
    for t in thread_list:
        t.start()
    for t in thread_list:
        t.join()
        
    total_sent = sum(row[0] for row in result_list)
    total_received = sum(row[1] for row in result_list)
    duration = max(row[2] for row in result_list)

    print("Sent: {}, received: {}, total time: {:.2f}".format(total_sent, total_received, duration))


if __name__ == "__main__":
    main()
