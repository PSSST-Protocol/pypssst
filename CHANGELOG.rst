Python PSSST Change History
===========================

Version 0.2.1
-------------

The reply handlers returned when packing and unpacking requests have
been refactored to prevent them being used more than once. The default
cipher suite uses AES in GCM mode, as a result sending more than once
reply packet (which would use the same key and nonce) would be a
security risk and so raises an error.

Version 0.2.0
-------------

This is the first version to be considered *stable*. Going forward the
implementation of each cipher suite will remain compatible with the previous
and future implementations. Documentation has been released to the project
page at https://pssst.readthedocs.io

