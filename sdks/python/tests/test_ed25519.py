import hashlib
import unittest

from qadamar import ed25519

import signer

# RFC 8032 section 7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc) (secret key, public key, message, signature)
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf", hashlib.sha512(b"abc").hexdigest(),
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]


class Rfc8032Vectors(unittest.TestCase):
    def test_vectors_verify(self):
        for _, public, message, signature in VECTORS:
            with self.subTest(public=public[:8]):
                self.assertTrue(ed25519.verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)))

    def test_test_signer_reproduces_the_vectors(self):
        for secret, public, message, signature in VECTORS:
            self.assertEqual(signer.public_key(bytes.fromhex(secret)).hex(), public)
            self.assertEqual(signer.sign(bytes.fromhex(secret), bytes.fromhex(message)).hex(), signature)

    def test_tampering_is_refused(self):
        _, public, message, signature = VECTORS[2]
        pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
        self.assertFalse(ed25519.verify(pk, msg + b"\x00", sig))
        self.assertFalse(ed25519.verify(pk, b"\xaf\x83", sig))
        for i in (0, 31, 32, 63):
            flipped = bytearray(sig)
            flipped[i] ^= 1
            self.assertFalse(ed25519.verify(pk, msg, bytes(flipped)))
        self.assertFalse(ed25519.verify(bytes.fromhex(VECTORS[0][1]), msg, sig), "another key")

    def test_malformed_inputs_are_refused(self):
        _, public, message, signature = VECTORS[1]
        pk, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
        self.assertFalse(ed25519.verify(pk[:31], msg, sig))
        self.assertFalse(ed25519.verify(pk, msg, sig[:63]))
        self.assertFalse(ed25519.verify(pk, msg, sig + b"\x00"))
        # s >= L (the group order): s + L is the same scalar mod L, refused as non-canonical (malleability)
        s = int.from_bytes(sig[32:], "little") + ed25519.q
        self.assertFalse(ed25519.verify(pk, msg, sig[:32] + s.to_bytes(32, "little")))
        # y >= p is not a canonical point encoding; y = 2 is not on the curve
        self.assertFalse(ed25519.is_public_key((ed25519.p + 1).to_bytes(32, "little")))
        self.assertFalse(ed25519.is_public_key((2).to_bytes(32, "little")))
        self.assertFalse(ed25519.verify((2).to_bytes(32, "little"), msg, sig))
        # x = 0 with the sign bit set is not a canonical encoding (y = p - 1 gives x2 = 0 only after reduction)
        self.assertFalse(ed25519.is_public_key(((ed25519.p - 1) | (1 << 255)).to_bytes(32, "little")))
        self.assertTrue(ed25519.is_public_key(pk))


if __name__ == "__main__":
    unittest.main()
