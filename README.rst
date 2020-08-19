PSSST: Packet Security for Stateless Server Transactions
========================================================

This module implements the PSSST protocol and provides a very simple interface for client and server endpoints.
PSSST is designed to provide a light weight way for clients to securely communicate with servers.

.. code-block:: python

    client = pssst.PSSSTClient(server_public_key)
    server = pssst.PSSSTServer(server_private_key)

    request_message = b"The Magic Words are Squeamish Ossifrage"

    # Pack the message with the client and unpack it with the server
    request_packet, client_reply_handler = client.pack_request(request_message)
    received_request, client_auth_key, server_reply_handler = server.unpack_request(request_packet)

    # Echo the request back from the server to the client
    reply_packet = server_reply_handler(received_request)
    received_reply = client_reply_handler(reply_packet)
   
