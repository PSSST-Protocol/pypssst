import pssst
import pytest

def test_unsupported_ciphers():
    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        pssst.generate_key_pair(cipher_suite=pssst.CipherSuite.NONE)

    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        pssst.PSSSTClient(b'\x55'*32, cipher_suite=pssst.CipherSuite.NONE)

    with pytest.raises(pssst.PSSSTUnsupportedCipher):
        pssst.PSSSTServer(b'\x55'*32, cipher_suite=pssst.CipherSuite.NONE)

