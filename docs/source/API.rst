The PSSST Python API
====================

The two parties in communication using PSSST are represented by
instances of the :any:`PSSSTClient` and :any:`PSSSTServer`
classes. Outgoing packets from the client are packed using the
client's :any:`pack_request` method and unpacked at the server using
the :any:`unpack_request` method. As well as returning the packed or
unpacked packts, each of these return a *reply handler* that can be
called to pack and unpack the reply packet. Note that in order to
ensure that more than one set of data is ever encrypted with the same
key and nonce each reply handler will raise a
:any:`PSSSTHandlerReused` error if it is called more than once.

The PSSSTClient class
---------------------

.. autoclass:: pssst.PSSSTClient
   :members:
   :member-order: bysource

The PSSSTServer class
---------------------

.. autoclass:: pssst.PSSSTServer
   :members:
   :member-order: bysource

Utility functions
-----------------

.. autofunction:: pssst.generate_key_pair

                  
Constants
---------

.. autoclass:: pssst.CipherSuite
   :exclude-members: NONE, X25519_AESGCM128
                     
   .. autoattribute:: X25519_AESGCM128


Exceptions
----------

.. autoclass:: pssst.PSSSTException

.. autoclass:: pssst.PSSSTUnsupportedCipher

.. autoclass:: pssst.PSSSTClientAuthFailed

.. autoclass:: pssst.PSSSTReplyMismatch

.. autoclass:: pssst.PSSSTNotReply

.. autoclass:: pssst.PSSSTNotRequest

.. autoclass:: pssst.PSSSTDecryptFailed

.. autoclass:: pssst.PSSSTHandlerReused
               

