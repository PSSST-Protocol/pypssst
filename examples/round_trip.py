#!/usr/bin/env python

"""
A trivial example of round-trip packet processing using PSSST"
"""

import pssst

def main():
    server_private_key, server_public_key = pssst.generate_key_pair()

    client = pssst.PSSSTClient(server_public_key)
    server = pssst.PSSSTServer(server_private_key)

    request_message = b"The Magic Words are Squeamish Ossifrage"

    # Pack the message with the client and unpack it with the server
    request_packet, client_reply_handler = client.pack_request(request_message)
    received_request, client_auth_key, server_reply_handler = server.unpack_request(request_packet)

    # Echo the request back from the server to the client
    reply_packet = server_reply_handler(received_request)
    received_reply = client_reply_handler(reply_packet)

    if received_reply == request_message:
        print("Success")
    else:
        print("Failed!")

if __name__ == "__main__":
    main()
