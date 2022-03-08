# pylint: disable=line-too-long

"""XBOX CRC utilities.

Based on XKCRC from https://github.com/mborgerson/xbeeprom:

Copyright 2020 Mike Davis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import struct
from typing import Tuple


def quick_crc(data: bytes, initial_state=None) -> Tuple[int, Tuple[int, int]]:
    """Performs XBOX CRC calculation on the given bytes.

    Data must be evenly divisible by 4.

    Returns (crc, (state_1, state_2))
    """
    if initial_state == None:
        initial_state = (0, 0)

    high = initial_state[0]
    low = initial_state[1]

    for i in range(len(data) // 4):
        start = i * 4
        val = struct.unpack("<L", data[start : start + 4])[0]
        sum = (high << 32) + low

        high = ((sum + val) >> 32) & 0xFFFFFFFF
        low = (low + val) & 0xFFFFFFFF

    value = ~((high + low) & 0xFFFFFFFF)
    if value < 0:
        value += 1 << 32

    return value, (high, low)
