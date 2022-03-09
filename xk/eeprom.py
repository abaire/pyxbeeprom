# pylint: disable=line-too-long

"""Utility methods for interacting with an XBOX EEPROM dump.

Based on XKEEPROM from https://github.com/mborgerson/xbeeprom:

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
**	     XKEEPROM.H - XBOX EEPROM Class' Header
********************************************************************************************************
**
**	This is the Class Header, see the .CPP file for more comments and implementation details.
**
********************************************************************************************************

********************************************************************************************************
**	CREDITS:
********************************************************************************************************
**	XBOX-LINUX TEAM:
**  ---------------
**		Wow, you guys are awsome !!  I bow down to your greatness !!  the "Friday 13th" Middle
**		Message Hack really saved our butts !!
**		REFERENCE URL:  http://xbox-linux.sourceforge.net
**
********************************************************************************************************
"""

import binascii
import ctypes
import enum
import logging
import struct
import sys
from typing import Any
from typing import Optional

from . import crc
from . import rc4
from . import sha1

logger = logging.getLogger(__name__)

EEPROM_SIZE = 0x100
CONFOUNDER_SIZE = 0x008
HDDKEY_SIZE = 0x010
XBEREGION_SIZE = 0x001
SERIALNUMBER_SIZE = 0x00C
MACADDRESS_SIZE = 0x006
ONLINEKEY_SIZE = 0x010
DVDREGION_SIZE = 0x001
VIDEOSTANDARD_SIZE = 0x004


class XBOX_VERSION(enum.IntEnum):
    V_NONE = 0x00
    V1_0 = 0x0A
    V1_1 = 0x0B
    V1_6 = 0x0C


class DVD_ZONE(enum.Enum):
    ZONE_NONE = 0x00
    ZONE1 = 0x01
    ZONE2 = 0x02
    ZONE3 = 0x03
    ZONE4 = 0x04
    ZONE5 = 0x05
    ZONE6 = 0x06


class VIDEO_STANDARD(enum.Enum):
    VID_INVALID = 0x00000000
    NTSC_M = 0x00400100
    PAL_I = 0x00800300


class XBE_REGION(enum.Enum):
    XBE_INVALID = 0x00
    NORTH_AMERICA = 0x01
    JAPAN = 0x02
    EURO_AUSTRALIA = 0x04


class AudioMode(enum.Enum):
    """Enumerates the possible speaker modes."""

    SURROUND = 1
    STEREO = 2
    MONO = 3


class VideoSettings(ctypes.LittleEndianStructure):
    """Fields within the VideoFlags"""

    _fields_ = [
        ("_unknown", ctypes.c_uint32, 16),
        ("Widescreen", ctypes.c_uint32, 1),
        ("Resolution720p", ctypes.c_uint32, 1),
        ("Resolution1080i", ctypes.c_uint32, 1),
        ("Resolution480p", ctypes.c_uint32, 1),
        ("Letterbox", ctypes.c_uint32, 1),
        ("_unknown2", ctypes.c_uint32, 2),
        ("Refresh60Hz", ctypes.c_uint32, 1),
    ]

    def __new__(cls, *args, **kwargs):
        if args:
            return cls.from_buffer_copy(args[0].to_bytes(4, byteorder=sys.byteorder))
        return super().__new__()

    def __str__(self):
        elements = []
        elements.append(f"Widescreen: {self.Widescreen}")
        elements.append(f"Letterbox: {self.Letterbox}")
        elements.append(f"Resolution480p: {self.Resolution480p}")
        elements.append(f"Resolution720p: {self.Resolution720p}")
        elements.append(f"Resolution1080i: {self.Resolution1080i}")
        elements.append(f"Refresh60Hz: {self.Refresh60Hz}")
        return "\n".join(elements)


class AudioSettings(ctypes.LittleEndianStructure):
    """Fields within the VideoFlags"""

    _fields_ = [
        ("Mono", ctypes.c_uint32, 1),
        ("Surround", ctypes.c_uint32, 1),
        ("_unknown", ctypes.c_uint32, 14),
        ("AC3", ctypes.c_uint32, 1),
        ("DTS", ctypes.c_uint32, 1),
    ]

    def __new__(cls, *args, **kwargs):
        if args:
            return cls.from_buffer_copy(args[0].to_bytes(4, byteorder=sys.byteorder))
        return super().__new__()

    def __str__(self):
        elements = []
        elements.append(f"Mono: {self.Mono}")
        elements.append(f"Surround: {self.Surround}")
        elements.append(f"AC3: {self.AC3}")
        elements.append(f"DTS: {self.DTS}")
        return "\n".join(elements)


class EEPROMData(ctypes.LittleEndianStructure):
    _pack_ = 1

    _SHA_TYPE = ctypes.c_uint8 * 20
    _CONFOUNDER_TYPE = ctypes.c_uint8 * 8
    _HDDKEY_TYPE = ctypes.c_uint8 * 16

    _fields_ = [
        ("HMAC_SHA1_Hash", _SHA_TYPE),  # 0x00 - 0x13 HMAC_SHA1 Hash
        ("Confounder", _CONFOUNDER_TYPE),  # 0x14 - 0x1B RC4 Encrypted Confounder ??
        ("HDDKey", _HDDKEY_TYPE),  # 0x1C - 0x2B RC4 Encrypted HDD key
        (
            "XBERegion",
            ctypes.c_uint32,
        ),  # 0x2C - 0x2F RC4 Encrypted Region code (0x01 North America, 0x02 Japan, 0x04 Europe)
        ("Checksum2", ctypes.c_uint32),  # 0x30 - 0x33 Checksum of next 44 bytes
        ("SerialNumber", ctypes.c_uint8 * 12),  # 0x34 - 0x3F Xbox serial number
        ("MACAddress", ctypes.c_uint8 * 6),  # 0x40 - 0x45 Ethernet MAC address
        ("UNKNOWN2", ctypes.c_uint8 * 2),  # 0x46 - 0x47  Unknown Padding ?
        ("OnlineKey", ctypes.c_uint8 * 16),  # 0x48 - 0x57 Online Key ?
        (
            "VideoStandard",
            ctypes.c_uint32,
        ),  # 0x58 - 0x5B  ** 0x00014000 = NTSC, 0x00038000 = PAL
        ("UNKNOWN3", ctypes.c_uint8 * 4),  # 0x5C - 0x5F  Unknown Padding ?
        # Comes configured up to here from factory..  everything after this can be zero'd out...
        # To reset XBOX to Factory settings, Make checksum3 0xFFFFFFFF and zero all data below (0x64-0xFF)
        # Doing this will Reset XBOX and upon startup will get Language & Setup screen...
        ("Checksum3", ctypes.c_uint32),  # 0x60 - 0x63  other Checksum of next
        ("TimeZoneBias", ctypes.c_uint32),  # 0x64 - 0x67 Zone Bias?
        ("TimeZoneStdName", ctypes.c_uint32),  # 0x68 - 0x6B Standard timezone
        ("TimeZoneDltName", ctypes.c_uint32),  # 0x5C - 0x6F Daylight timezone
        ("UNKNOWN4", ctypes.c_uint8 * 8),  # 0x70 - 0x77 Unknown Padding ?
        (
            "TimeZoneStdDate",
            ctypes.c_uint32,
        ),  # 0x78 - 0x7B 10-05-00-02 (Month-Day-DayOfWeek-Hour)
        (
            "TimeZoneDltDate",
            ctypes.c_uint32,
        ),  # 0x7C - 0x7F 04-01-00-02 (Month-Day-DayOfWeek-Hour)
        ("UNKNOWN5", ctypes.c_uint8 * 8),  # 0x80 - 0x87 Unknown Padding ?
        ("TimeZoneStdBias", ctypes.c_uint32),  # 0x88 - 0x8B Standard Bias?
        ("TimeZoneDltBias", ctypes.c_uint32),  # 0x8C - 0x8F Daylight Bias?
        ("LanguageID", ctypes.c_uint32),  # 0x90 - 0x93 Language ID
        ("VideoFlags", ctypes.c_uint32),  # 0x94 - 0x97 Video Settings
        ("AudioFlags", ctypes.c_uint32),  # 0x98 - 0x9B Audio Settings
        ("ParentalControlGames", ctypes.c_uint32),  # 0x9C - 0x9F 0=MAX rating
        (
            "ParentalControlPwd",
            ctypes.c_uint32,
        ),  # 0xA0 - 0xA3 7=X, 8=Y, B=LTrigger, C=RTrigger
        ("ParentalControlMovies", ctypes.c_uint32),  # 0xA4 - 0xA7 0=Max rating
        ("XBOXLiveIPAddress", ctypes.c_uint32),  # 0xA8 - 0xAB XBOX Live IP Address..
        ("XBOXLiveDNS", ctypes.c_uint32),  # 0xAC - 0xAF XBOX Live DNS Server..
        (
            "XBOXLiveGateWay",
            ctypes.c_uint32,
        ),  # 0xB0 - 0xB3 XBOX Live Gateway Address..
        (
            "XBOXLiveSubNetMask",
            ctypes.c_uint32,
        ),  # 0xB4 - 0xB7 XBOX Live Subnet Mask..
        ("OtherSettings", ctypes.c_uint32),  # 0xA8 - 0xBB Other XBLive settings ?
        ("DVDPlaybackKitZone", ctypes.c_uint32),  # 0xBC - 0xBF DVD Playback Kit Zone
        ("UNKNOWN6", ctypes.c_uint8 * 64),  # 0xC0 - 0xFF Unknown Codes / History ?
    ]

    def __init__(self, *args: Any, **kw: Any):
        self._encrypted = True
        super().__init__(*args, **kw)

    @property
    def audio_mode(self):
        audio = AudioSettings(self.AudioFlags)
        if audio.Surround:
            return AudioMode.SURROUND
        if audio.Mono:
            return AudioMode.MONO
        return AudioMode.STEREO

    @audio_mode.setter
    def audio_mode(self, value):
        audio = AudioSettings(self.AudioFlags)
        if value == AudioMode.SURROUND:
            audio.Surround = 1
            audio.Mono = 0
        elif value == AudioMode.MONO:
            audio.Surround = 0
            audio.Mono = 1
        else:
            audio.Surround = 0
            audio.Mono = 0

        self._update_audio_flags(audio)

    @property
    def dolby_digital_flag(self) -> bool:
        audio = AudioSettings(self.AudioFlags)
        return audio.AC3

    @dolby_digital_flag.setter
    def dolby_digital_flag(self, value):
        audio = AudioSettings(self.AudioFlags)
        audio.AC3 = value
        self._update_audio_flags(audio)

    @property
    def dts_flag(self) -> bool:
        audio = AudioSettings(self.AudioFlags)
        return audio.DTS

    @dts_flag.setter
    def dts_flag(self, value):
        audio = AudioSettings(self.AudioFlags)
        audio.DTS = value
        self._update_audio_flags(audio)

    def _update_audio_flags(self, audio_settings: AudioSettings):
        self.AudioFlags = struct.unpack("<L", bytearray(audio_settings))[0]

    def decrypt(self) -> Optional[XBOX_VERSION]:
        """Decrypt EEPROM using auto-detect by means of the SHA1 Middle Message hack."""
        xbox_version = XBOX_VERSION.V1_0
        raw_data = bytearray(self)
        hmac_sha_bytes = bytearray(self.HMAC_SHA1_Hash)

        while xbox_version < 13:
            hasher = sha1.SHA1()

            key_hash = hasher.xbox_hmac_sha1(xbox_version, raw_data[:20])

            rc4_key = rc4.RC4(key_hash)
            decrypted_confounder = rc4_key.apply(bytearray(self.Confounder))
            decrypted_hdd_key = rc4_key.apply(bytearray(self.HDDKey))
            decrypted_region = struct.unpack(
                "<L", rc4_key.apply(struct.pack("<L", self.XBERegion))
            )[0]

            # re-create data_hash from decrypted data
            confirm_hash = self._build_hmac_sha(
                xbox_version, decrypted_confounder, decrypted_hdd_key, decrypted_region
            )

            if confirm_hash == hmac_sha_bytes:
                self._encrypted = False
                self.Confounder = self._CONFOUNDER_TYPE.from_buffer(
                    decrypted_confounder
                )
                self.HDDKey = self._HDDKEY_TYPE.from_buffer(decrypted_hdd_key)
                self.XBERegion = decrypted_region
                return XBOX_VERSION(xbox_version)

            xbox_version += 1
        raise Exception("Failed to decrypt EEPROM")

    def _build_hmac_sha(self, xbox_version, confounder, hddkey, xberegion):
        hasher = sha1.SHA1()
        ret = hasher.xbox_hmac_sha1(
            xbox_version,
            bytearray(confounder),
            bytearray(hddkey),
            struct.pack("<L", xberegion),
        )
        return ret

    def encrypt(self, xbox_version: XBOX_VERSION) -> bytearray:
        if self._encrypted:
            return bytearray(self)

        confounder_bytes = bytearray(self.Confounder)
        hddkey_bytes = bytearray(self.HDDKey)

        hmac_sha = self._build_hmac_sha(
            xbox_version, confounder_bytes, hddkey_bytes, self.XBERegion
        )
        self.HMAC_SHA1_Hash = self._SHA_TYPE.from_buffer(hmac_sha)

        # Calculate rc4 key initializer data from eeprom key and data_hash.
        hasher = sha1.SHA1()
        key_hash = hasher.xbox_hmac_sha1(xbox_version, self.HMAC_SHA1_Hash)

        rc4_key = rc4.RC4(key_hash)
        self.Confounder = self._CONFOUNDER_TYPE.from_buffer(
            rc4_key.apply(confounder_bytes)
        )
        self.HDDKey = self._HDDKEY_TYPE.from_buffer(rc4_key.apply(hddkey_bytes))
        self.XBERegion = struct.unpack(
            "<L", rc4_key.apply(struct.pack("<L", self.XBERegion))
        )[0]

        self._update_checksums()

        self._encrypted = True

    def _update_checksums(self):
        def pack(val):
            return struct.pack("<L", val)

        val, state = crc.quick_crc(bytearray(self.SerialNumber))
        val, state = crc.quick_crc(bytearray(self.MACAddress), state)
        val, state = crc.quick_crc(bytearray(self.UNKNOWN2), state)
        val, state = crc.quick_crc(bytearray(self.OnlineKey), state)
        val, state = crc.quick_crc(pack(self.VideoStandard), state)
        val, _ = crc.quick_crc(bytearray(self.UNKNOWN3), state)
        self.Checksum2 = val

        val, state = crc.quick_crc(pack(self.TimeZoneBias))
        val, state = crc.quick_crc(pack(self.TimeZoneStdName), state)
        val, state = crc.quick_crc(pack(self.TimeZoneDltName), state)
        val, state = crc.quick_crc(bytearray(self.UNKNOWN4), state)
        val, state = crc.quick_crc(pack(self.TimeZoneStdDate), state)
        val, state = crc.quick_crc(pack(self.TimeZoneDltDate), state)
        val, state = crc.quick_crc(bytearray(self.UNKNOWN5), state)
        val, state = crc.quick_crc(pack(self.TimeZoneStdBias), state)
        val, state = crc.quick_crc(pack(self.TimeZoneDltBias), state)
        val, state = crc.quick_crc(pack(self.LanguageID), state)
        val, state = crc.quick_crc(pack(self.VideoFlags), state)
        val, state = crc.quick_crc(pack(self.AudioFlags), state)
        val, state = crc.quick_crc(pack(self.ParentalControlGames), state)
        val, state = crc.quick_crc(pack(self.ParentalControlPwd), state)
        val, state = crc.quick_crc(pack(self.ParentalControlMovies), state)
        val, state = crc.quick_crc(pack(self.XBOXLiveIPAddress), state)
        val, state = crc.quick_crc(pack(self.XBOXLiveDNS), state)
        val, state = crc.quick_crc(pack(self.XBOXLiveGateWay), state)
        val, state = crc.quick_crc(pack(self.XBOXLiveSubNetMask), state)
        val, state = crc.quick_crc(pack(self.OtherSettings), state)
        val, _ = crc.quick_crc(pack(self.DVDPlaybackKitZone), state)
        self.Checksum3 = val

    def __str__(self):
        elements = []
        elements.append(f"HMAC SHA1: {binascii.hexlify(self.HMAC_SHA1_Hash)}")
        elements.append(f"HDD Key: {binascii.hexlify(self.HDDKey)}")

        elements.append(f"Region: {XBE_REGION(self.XBERegion)}")

        elements.append(f"Serial #: {binascii.hexlify(self.SerialNumber)}")
        elements.append(f"MAC Address: {binascii.hexlify(self.MACAddress)}")
        elements.append(f"OnlineKey: {binascii.hexlify(self.OnlineKey)}")
        elements.append(f"VideoStandard: {VIDEO_STANDARD(self.VideoStandard)}")

        elements.append(f"TimeZoneBias {self.TimeZoneBias}")
        elements.append(f"TimeZoneStdName {self.TimeZoneStdName}")
        elements.append(f"TimeZoneDltName {self.TimeZoneDltName}")
        elements.append(f"TimeZoneStdDate {self.TimeZoneStdDate}")
        elements.append(f"TimeZoneDltDate {self.TimeZoneDltDate}")
        elements.append(f"TimeZoneStdBias {self.TimeZoneStdBias}")
        elements.append(f"TimeZoneDltBias {self.TimeZoneDltBias}")

        elements.append(f"LanguageID {self.LanguageID}")

        vid = VideoSettings(self.VideoFlags)
        elements.append(f"VideoFlags {vid}")

        audio = AudioSettings(self.AudioFlags)
        elements.append(f"AudioFlags {audio}")
        elements.append(f"ParentalControlGames {self.ParentalControlGames}")
        elements.append(f"ParentalControlPwd {self.ParentalControlPwd:x}")
        elements.append(f"ParentalControlMovies {self.ParentalControlMovies}")

        elements.append(f"XBOXLiveIPAddress {self.XBOXLiveIPAddress:x}")
        elements.append(f"XBOXLiveDNS {self.XBOXLiveDNS:x}")
        elements.append(f"XBOXLiveGateWay {self.XBOXLiveGateWay:x}")
        elements.append(f"XBOXLiveSubNetMask {self.XBOXLiveSubNetMask:x}")

        elements.append(f"DVDPlaybackKitZone {DVD_ZONE(self.DVDPlaybackKitZone)}")
        return "\n".join(elements)


class EEPROM:
    """Provides functionality to manipulate XBOX EEPROM data."""

    def __init__(self):
        self._data: Optional[EEPROMData] = None
        self._raw_data: Optional[bytes] = None
        self._encrypted = True
        self._version = None

    def read_from_bin_file(self, file: str, encrypted=True):
        """Update the contents of this instance from the given BIN dump."""
        with open(file, "rb") as infile:
            self._raw_data = infile.read(EEPROM_SIZE)
            self._data = EEPROMData.from_buffer_copy(self._raw_data)
        self._encrypted = encrypted
        if encrypted:
            self.decrypt()

    def log_info(self):
        """Dumps the EEPROMData to log output."""
        self.decrypt()
        logger.info(f" {self._version.name}\n{self._data}\n")

    def decrypt(self):
        """Decrypt EEPROM using auto-detect by means of the SHA1 Middle Message hack."""
        if not self._encrypted:
            return
        self._version = self._data.decrypt()
        self._encrypted = False

    def encrypt(self) -> bytearray:
        """Encrypts the current EEPROM state and returns it in a buffer."""
        self._data.encrypt(self._version)
        return bytearray(self._data)

    @property
    def audio_mode(self):
        return self._data.audio_mode

    @audio_mode.setter
    def audio_mode(self, value):
        self._data.audio_mode = value

    @property
    def dolby_digital_flag(self) -> bool:
        return self._data.dolby_digital_flag

    @dolby_digital_flag.setter
    def dolby_digital_flag(self, value):
        self._data.dolby_digital_flag = value

    @property
    def dts_flag(self) -> bool:
        return self._data.dts_flag

    @dts_flag.setter
    def dts_flag(self, value):
        self._data.dts_flag = value
