# pylint: disable=line-too-long

"""SHA1 utilities.

Based on XKSHA1 from https://github.com/mborgerson/xbeeprom:

**********************************
**********************************
**      BROUGHT TO YOU BY:		**
**********************************
**********************************
**								**
**		  [TEAM ASSEMBLY]		**
**								**
**		www.team-assembly.com	**
**								**
******************************************************************************************************
* This is free software you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
******************************************************************************************************


********************************************************************************************************
**	     XKSHA1.H - General SHA1 and HMAC_SHA1 Class' Header
********************************************************************************************************
**
**	This is the Class Header, see the .CPP file for more comments and implementation details.
**
**      This file implements the Secure Hashing Algorithm 1 as
**      defined in FIPS PUB 180-1 published April 17, 1995.
**
**
**		Added Funcionality to NOT require the KEY when doing HMAC_SHA1 hashes
**		as per xbox-Linux groups "Fridaym 13th Middle Message Hack"
**
********************************************************************************************************


********************************************************************************************************
**	CREDITS:
********************************************************************************************************
**	SPEEDBUMP:
**		My utmost greatfullness and admiration goes towards SpeedBump for all his hard work..
**		I used most of his code and converted to C++ objects etc..
**
**	XBOX-LINUX TEAM:
**  ---------------
**		In particular "Franz", Wow, you guys are awsome !!  I bow down to your greatness !!
**		The "Friday 13th" Middle Message Hack really saved our butts !!
**		REFERENCE URL:  http://xbox-linux.sourceforge.net
**
********************************************************************************************************
"""
import binascii


def _circular_shift(bits, word):
    value = (word << bits) & 0xFFFFFFFF
    value |= (word >> (32 - bits)) & 0xFFFFFFFF
    return value


class SHA1:
    """Provides SHA1 hash functionality."""

    def __init__(self):
        self._computed = False
        self._intermediate_hash = []
        self._length_low = 0
        self._length_high = 0
        self._message_block = bytearray(64)
        self._message_block_index = 0
        self.reset()

    def xbox_hmac_sha1(self, version: int, *args) -> bytearray:
        """Computes the HMAC_SHA1 for the given fields using the given XBOX version."""
        self._hmac1_reset(version)
        for arg in args:
            self._sha1_input(arg)

        result = self._sha1_result()
        for i, byte in enumerate(result):
            self._message_block[i] = byte

        self._hmac2_reset(version)

        self._sha1_input(self._message_block[0:20])
        result = self._sha1_result()
        return result

    def _sha1_input(self, bytes_to_process):
        for byte_value in bytes_to_process:
            self._message_block[self._message_block_index] = byte_value & 0xFF
            self._message_block_index += 1

            self._length_low += 8
            if self._length_low > 0xFFFFFFFF:
                self._length_low = 0
                self._length_high += 1
                if self._length_high > 0xFFFFFFFF:
                    raise Exception("Message is too long")
            if self._message_block_index == 64:
                self._process_message_block()

    def _sha1_result(self) -> bytearray:
        if not self._computed:
            self._pad_message()
            for i in range(64):
                # message may be sensitive, clear it out
                self._message_block[i] = 0
            self._length_low = 0
            self._length_high = 0
            self._computed = True

        result = bytearray()
        for i in range(20):
            value = self._intermediate_hash[i >> 2] >> 8 * (3 - (i & 0x03))
            result.append(value & 0xFF)
        return result

    def _hmac1_reset(self, version):
        self.reset()

        if version == 9:
            self._intermediate_hash = [
                0x85F9E51A,
                0xE04613D2,
                0x6D86A50C,
                0x77C32E3C,
                0x4BD717A4,
            ]
        elif version == 10:
            self._intermediate_hash = [
                0x72127625,
                0x336472B9,
                0xBE609BEA,
                0xF55E226B,
                0x99958DAC,
            ]
        elif version == 11:
            self._intermediate_hash = [
                0x39B06E79,
                0xC9BD25E8,
                0xDBC6B498,
                0x40B4389D,
                0x86BBD7ED,
            ]
        elif version == 12:
            self._intermediate_hash = [
                0x8058763A,
                0xF97D4E0E,
                0x865A9762,
                0x8A3D920D,
                0x08995B2C,
            ]
        else:
            raise Exception(f"Invalid `version` parameter {version} < 9 || > 12")

        self._length_low = 512

    def _hmac2_reset(self, version):
        self.reset()

        if version == 9:
            self._intermediate_hash = [
                0x5D7A9C6B,
                0xE1922BEB,
                0xB82CCDBC,
                0x3137AB34,
                0x486B52B3,
            ]
        elif version == 10:
            self._intermediate_hash = [
                0x76441D41,
                0x4DE82659,
                0x2E8EF85E,
                0xB256FACA,
                0xC4FE2DE8,
            ]
        elif version == 11:
            self._intermediate_hash = [
                0x9B49BED3,
                0x84B430FC,
                0x6B8749CD,
                0xEBFE5FE5,
                0xD96E7393,
            ]
        elif version == 12:
            self._intermediate_hash = [
                0x01075307,
                0xA2F1E037,
                0x1186EEEA,
                0x88DA9992,
                0x168A5609,
            ]
        else:
            raise Exception(f"Invalid `version` parameter {version} < 9 || > 12")

        self._length_low = 512

    def reset(self):
        """Fully resets this instance in preparation for processing a new message."""
        self._length_low = 0
        self._length_high = 0
        self._message_block_index = 0
        self._intermediate_hash = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
        self._computed = False

    def _process_message_block(self):
        K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

        W = []
        for t in range(16):
            value = (self._message_block[t * 4] << 24) & 0xFF000000
            value |= (self._message_block[t * 4 + 1] << 16) & 0x00FF0000
            value |= (self._message_block[t * 4 + 2] << 8) & 0x0000FF00
            value |= (self._message_block[t * 4 + 3]) & 0x000000FF
            W.append(value)

        for t in range(16, 80):
            W.append(_circular_shift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]))

        A = self._intermediate_hash[0]
        B = self._intermediate_hash[1]
        C = self._intermediate_hash[2]
        D = self._intermediate_hash[3]
        E = self._intermediate_hash[4]

        for t in range(20):
            temp = _circular_shift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0]
            temp &= 0xFFFFFFFF
            E = D
            D = C
            C = _circular_shift(30, B)

            B = A
            A = temp

        for t in range(20, 40):
            temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[1]
            temp &= 0xFFFFFFFF
            E = D
            D = C
            C = _circular_shift(30, B)
            B = A
            A = temp

        for t in range(40, 60):
            temp = (
                _circular_shift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2]
            )
            temp &= 0xFFFFFFFF
            E = D
            D = C
            C = _circular_shift(30, B)
            B = A
            A = temp

        for t in range(60, 80):
            temp = _circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[3]
            temp &= 0xFFFFFFFF
            E = D
            D = C
            C = _circular_shift(30, B)
            B = A
            A = temp

        self._intermediate_hash[0] = (self._intermediate_hash[0] + A) & 0xFFFFFFFF
        self._intermediate_hash[1] = (self._intermediate_hash[1] + B) & 0xFFFFFFFF
        self._intermediate_hash[2] = (self._intermediate_hash[2] + C) & 0xFFFFFFFF
        self._intermediate_hash[3] = (self._intermediate_hash[3] + D) & 0xFFFFFFFF
        self._intermediate_hash[4] = (self._intermediate_hash[4] + E) & 0xFFFFFFFF

        self._message_block_index = 0

    def _pad_message(self):
        # Check to see if the current message block is too small to hold the initial
        # padding bits and length. If so, we will pad the block, process it, and then
        # continue padding into a second block.

        if self._message_block_index > 55:
            self._message_block[self._message_block_index] = 0x80
            self._message_block_index += 1

            while self._message_block_index < 64:
                self._message_block[self._message_block_index] = 0
                self._message_block_index += 1

            self._process_message_block()

            while self._message_block_index < 56:
                self._message_block[self._message_block_index] = 0
                self._message_block_index += 1
        else:
            self._message_block[self._message_block_index] = 0x80
            self._message_block_index += 1

            while self._message_block_index < 56:
                self._message_block[self._message_block_index] = 0
                self._message_block_index += 1

        # Store the message length as the last 8 octets
        self._message_block[56] = self._length_high >> 24
        self._message_block[57] = self._length_high >> 16
        self._message_block[58] = self._length_high >> 8
        self._message_block[59] = self._length_high & 0xFF
        self._message_block[60] = self._length_low >> 24
        self._message_block[61] = self._length_low >> 16
        self._message_block[62] = self._length_low >> 8
        self._message_block[63] = self._length_low & 0xFF

        self._process_message_block()
