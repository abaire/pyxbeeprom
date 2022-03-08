import unittest

from xk import crc


class CRCCase(unittest.TestCase):
    def test_crc_zeros(self):
        buffer = bytearray(20)
        val, _ = crc.quick_crc(buffer)
        self.assertEqual(0xFFFFFFFF, val)

    def test_crc_ramp(self):
        buffer = bytearray(20)
        for i in range(len(buffer)):
            buffer[i] = i
        val, _ = crc.quick_crc(buffer)
        self.assertEqual(0xC8CDD2D7, val)

    def test_crc_ramp_chained(self):
        buffer = bytearray(20)
        for i in range(len(buffer)):
            buffer[i] = i

        val, state = crc.quick_crc(buffer[:8])
        val, _ = crc.quick_crc(buffer[8:], state)
        self.assertEqual(0xC8CDD2D7, val)


if __name__ == "__main__":
    unittest.main()
