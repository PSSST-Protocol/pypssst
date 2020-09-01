Python PSSST documentation
==========================

Packet Security for Stateless Server Transactions (PSSST) is a light weight cryotographic
protocol to allow clients to securely send messages to a server or pool of servers,
and receive secure responses, in such a way that the servers do not need to maintain
any state in between calls. Unlike sessions-based protocols suchh as TLS (and SSL),
the protection of each request is self-contained and there is no "handshake", so
there is no added network latency when sending a request. Most importantly, since
there is no state kept at the server there is no need for complex load balancing
when a pool of servers is used. This allows systems to scale to millions of clients
relatively cheaply. PSSST also includes optional support for cryptographic authentication
of the client making the request (with very little added burden on the client when in
use), making it well suited to IoT applications.

Key features of PSSST are:

- No per-client state kept by servers between transactions
- No added network round-trips for handshake
- Small data overhead
- Optional client authentication


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   Introduction <introduction>
   API details <API>
   Contributing <contributing>
   License <license>
   Change log <changelog>

                  
Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
