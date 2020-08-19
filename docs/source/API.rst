The PSSST Python API
====================

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

               

