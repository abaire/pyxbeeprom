import binascii
import unittest

from xk import rc4


class RC4TestCase(unittest.TestCase):
    def test_zero_key(self):
        expected = binascii.unhexlify("DE188941A3375D3A8A061E67576E926DC71A7FA3")

        key_hash = bytearray(20)
        buffer = bytearray(20)

        encrypter = rc4.RC4(key_hash)
        result = encrypter.apply(buffer)

        self.assertEqual(binascii.hexlify(expected), binascii.hexlify(result))

    def test_ramp_key(self):
        expected = binascii.unhexlify("5E9740E23708B69E4AD4509C357605DDFCED9D3B")

        key_hash = bytearray(20)
        for i in range(20):
            key_hash[i] = i
        buffer = bytearray(20)

        encrypter = rc4.RC4(key_hash)
        result = encrypter.apply(buffer)

        self.assertEqual(binascii.hexlify(expected), binascii.hexlify(result))


if __name__ == "__main__":
    unittest.main()
