package dns

import (
	"crypto"
	"crypto/subtle"
	"math/big"

	"codeberg.org/miekg/dns/internal/pack"
)

// RSA public exponents that do not fit in an int.
//
// Go's crypto/rsa refuses any public exponent above 2^31-1, and rsa.PublicKey
// holds it in an int, so a key using a larger one cannot be represented let
// alone verified (golang/go#3161, open since 2012 and filed for this very
// reason). DNSSEC has such keys in it: BIND's dnssec-keygen offers "the next
// Fermat number" for -e, and zones took it up, so the F5 exponent 2^32+1
// appears in signed zones to this day.
//
// Verification with a public key needs nothing crypto/rsa does beyond a modular
// exponentiation, which math/big performs at any size. The signature is public,
// so none of this is secret-dependent.

// pkcs1v15Prefixes are the ASN.1 DigestInfo headers that precede the hash in a
// PKCS#1 v1.5 signature block, from RFC 8017 section 9.2.
var pkcs1v15Prefixes = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// publicKeyRSABig returns the modulus and exponent of an RSA DNSKEY without
// requiring the exponent to fit in an int. It returns nil for a key that is
// malformed in any way publicKeyRSA would also reject.
func (k *DNSKEY) publicKeyRSABig() (n, e *big.Int) {
	keybuf, err := pack.Base64([]byte(k.PublicKey))
	if err != nil {
		return nil, nil
	}
	if len(keybuf) < 1+1+64 {
		return nil, nil
	}

	// RFC 3110 section 2: the exponent length is in the first byte, or, if that
	// is zero, in the two bytes that follow.
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		if len(keybuf) < 3 {
			return nil, nil
		}
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}
	if explen == 0 {
		return nil, nil
	}
	modoff := keyoff + int(explen)
	if modoff >= len(keybuf) {
		return nil, nil
	}
	// Leading zeros are prohibited in both fields, and a modulus outside these
	// bounds is not a key this will verify against.
	if keybuf[keyoff] == 0 || keybuf[modoff] == 0 {
		return nil, nil
	}
	modlen := len(keybuf) - modoff
	if modlen < 64 || modlen > 512 {
		return nil, nil
	}

	e = new(big.Int).SetBytes(keybuf[keyoff:modoff])
	n = new(big.Int).SetBytes(keybuf[modoff:])
	if e.BitLen() < 2 || e.Bit(0) == 0 {
		// An exponent below 2, or an even one, is not usable.
		return nil, nil
	}
	return n, e
}

// verifyPKCS1v15Big checks a PKCS#1 v1.5 signature against a modulus and
// exponent of any size.
//
// The whole encoded block is rebuilt from the digest and compared against the
// one the signature decrypts to, rather than the block being taken apart and
// its pieces inspected. Parsing is where PKCS#1 v1.5 verifiers have
// historically gone wrong -- a verifier that skips over the padding instead of
// requiring it to be exactly right accepts forged signatures -- and a
// comparison of the entire block cannot make that mistake.
func verifyPKCS1v15Big(n, e *big.Int, hash crypto.Hash, hashed, sig []byte) error {
	prefix, ok := pkcs1v15Prefixes[hash]
	if !ok {
		return ErrAlg
	}
	if hash.Size() != len(hashed) {
		return ErrSig
	}

	size := (n.BitLen() + 7) / 8
	tLen := len(prefix) + len(hashed)
	// RFC 8017 section 9.2: at least eight bytes of padding, plus the two
	// leading bytes and the separator.
	if size < tLen+11 {
		return ErrKey
	}
	if len(sig) != size {
		return ErrSig
	}

	s := new(big.Int).SetBytes(sig)
	if s.Cmp(n) >= 0 {
		return ErrSig
	}
	decrypted := new(big.Int).Exp(s, e, n).FillBytes(make([]byte, size))

	expected := make([]byte, size)
	expected[0] = 0x00
	expected[1] = 0x01
	for i := 2; i < size-tLen-1; i++ {
		expected[i] = 0xff
	}
	expected[size-tLen-1] = 0x00
	copy(expected[size-tLen:], prefix)
	copy(expected[size-len(hashed):], hashed)

	if subtle.ConstantTimeCompare(decrypted, expected) != 1 {
		return ErrSig
	}
	return nil
}
