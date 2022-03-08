# pylint: disable=line-too-long

"""RC4 utilities.

Based on XKRC4 from https://github.com/mborgerson/xbeeprom:

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
* This is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
******************************************************************************************************

********************************************************************************************************
**	     XKRC4.CPP - General RC4 Encryption Class' Implementation
********************************************************************************************************
**
**	This is the Class Contains basic RC4 encryption functionality...
**
********************************************************************************************************


********************************************************************************************************
**	CREDITS:
********************************************************************************************************
**	SPEEDBUMP:
**	---------
**		My utmost greatfullness and admiration goes towards SpeedBump for all his hard work..
**		I used most of his code and converted to C++ objects etc..
**
**	XBOX-LINUX TEAM:
**	---------------
**		Wow, you guys are awsome !!  I bow down to your greatness !!
**		REFERENCE URL:  http://xbox-linux.sourceforge.net
**
********************************************************************************************************
"""


class RC4:
    """Provides RC4 functionality"""

    def __init__(self, key_data: bytes):
        self._state = bytearray(256)
        self._x = 0
        self._y = 0
        self._init_key(key_data)

    def _init_key(self, key_data):
        for i in range(256):
            self._state[i] = i
        self._x = 0
        self._y = 0

        index1 = 0
        index2 = 0

        for counter in range(256):
            index2 = (key_data[index1] + self._state[counter] + index2) % 256
            self._swap(counter, index2)
            index1 = (index1 + 1) % len(key_data)

    def apply(self, data: bytes) -> bytearray:
        """Encrypts (or decrypts) the given bytes, returning a new bytearray."""
        x = self._x
        y = self._y

        result = bytearray(data)

        for counter in range(len(data)):
            x = (x + 1) % 256
            y = (self._state[x] + y) % 256
            self._swap(x, y)
            xor_idx = (self._state[x] + self._state[y]) % 256
            result[counter] ^= self._state[xor_idx]

        self._x = x
        self._y = y

        return result

    def _swap(self, a_idx, b_idx):
        temp = self._state[a_idx]
        self._state[a_idx] = self._state[b_idx]
        self._state[b_idx] = temp
