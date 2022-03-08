import binascii
import unittest

from xk import sha1

class SHA1TestCase(unittest.TestCase):
    _VERSIONS = {0x0A, 0x0B, 0x0C}

    def test_verify_sha1_zeros(self):
        expected = {
            0x0A: binascii.unhexlify("AE3076F3ECCB6FEC2085F45EACBB61A89F45D944"),
            0x0B: binascii.unhexlify("B58B2FB57F9AC1E3505F3B38B9B8248756E0763E"),
            0x0C: binascii.unhexlify("DD3BECAD2D0E9A5576C642FE0A160BC187941756"),
        }

        test = bytearray(8)
        test2 = bytearray(20)

        for v in self._VERSIONS:
            s = sha1.SHA1()
            result = s.xbox_hmac_sha1(v, test, test2)
            self.assertEqual(binascii.hexlify(expected[v]), binascii.hexlify(result))


    def test_verify_sha1_ramp(self):
        expected = {
            0x0A: binascii.unhexlify("310D1D37F81114779AC33522550B8CD9B5C70D6D"),
            0x0B: binascii.unhexlify("EF74F3B133882E693911B4E4DABA89AF378C6D47"),
            0x0C: binascii.unhexlify("D0F9281B0871805D84A720482F19313F0B19F0C2"),
        }

        test = bytearray(8)
        for i in range(len(test)):
            test[i] = i
        test2 = bytearray(20)
        for i in range(len(test2)):
            test2[i] = i

        for v in self._VERSIONS:
            s = sha1.SHA1()
            result = s.xbox_hmac_sha1(v, test, test2)
            self.assertEqual(binascii.hexlify(expected[v]), binascii.hexlify(result))


if __name__ == '__main__':
    unittest.main()
