import pssst

def test_make_header():
    hdr = pssst.Header()
    assert not hdr.reply, "Default reply flag not false"
    assert not hdr.client_auth, "Default client_auth flag not false"
    assert hdr.cipher_suite == pssst.CipherSuite.NONE, "Default cipher suite not NONE"

def test_header_accessors():
    hdr = pssst.Header()

    hdr.reply = True
    assert hdr.reply, "reply flag not True"
    hdr.reply = False
    assert not hdr.reply, "reply flag not False"
    
    hdr.client_auth = True
    assert hdr.client_auth, "client_auth flag not True"
    hdr.client_auth = False
    assert not hdr.client_auth, "client_auth flag not False"

    hdr.cipher_suite = pssst.CipherSuite.X25519_AESGCM128
    assert hdr.cipher_suite == pssst.CipherSuite.X25519_AESGCM128, "Failed to set cipher suite"

def _check_bytes(hdr):
    h1_bytes = hdr.packet_bytes
    h2 = pssst.Header.from_packet(h1_bytes)
    h2_bytes = h2.packet_bytes
    assert h1_bytes == h2_bytes, "Header bytes failed round-trip"
    
def test_header_bytes():
    hdr = pssst.Header()
    _check_bytes(hdr)
    hdr = pssst.Header(cipher_suite=pssst.CipherSuite.X25519_AESGCM128)
    _check_bytes(hdr)
    hdr = pssst.Header(reply=True)
    _check_bytes(hdr)
    hdr = pssst.Header(client_auth=True)
    _check_bytes(hdr)

def test_repr():
    hdr = pssst.Header()
    assert repr(hdr) == "Header(cipher_suite=CipherSuite.NONE, reply=False, client_auth=False)", "String representation incorrect"
    
