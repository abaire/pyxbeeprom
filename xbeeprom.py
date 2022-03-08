#!/usr/bin/env python3
"""
XBOX EEPROM editing utility

Based on https://github.com/mborgerson/xbeeprom
"""
import argparse
import binascii
import logging
import os
import sys

import xk

logger = logging.getLogger(__name__)

_AUDIO_MODES = {
    "mono": xk.AudioMode.MONO,
    "stereo": xk.AudioMode.STEREO,
    "surround": xk.AudioMode.SURROUND,
}


def _main(args):
    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)

    eeprom = xk.EEPROM()
    eeprom.read_from_bin_file(os.path.realpath(os.path.expanduser(args.eeprom_file)))

    modified = False
    if args.audio_mode is not None:
        modified = True
        eeprom.audio_mode = _AUDIO_MODES[args.audio_mode]

    if args.enable_dolby_digital:
        modified = True
        eeprom.dolby_digital_flag = True
    if args.disable_dolby_digital:
        modified = True
        eeprom.dolby_digital_flag = False

    if args.enable_dts:
        modified = True
        eeprom.dts_flag = True
    if args.disable_dts:
        modified = True
        eeprom.dts_flag = False

    if not modified:
        eeprom.log_info()
        return

    encrypted = eeprom.encrypt()
    outfile_name = args.output
    if not outfile_name:
        outfile_name = args.eeprom_file + ".modified.bin"
    outfile_name = os.path.realpath(os.path.expanduser(outfile_name))
    with open(outfile_name, "wb") as outfile:
        outfile.write(encrypted)

    eeprom.log_info()


if __name__ == "__main__":

    def _parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "eeprom_file",
            help="The EEPROM file to operate on.",
        )

        parser.add_argument(
            "-o",
            "--output",
            metavar="filename",
            help="Filename to write modified contents to.",
        )

        parser.add_argument(
            "-v",
            "--verbose",
            help="Enable verbose debug output.",
            action="store_true",
        )

        parser.add_argument(
            "--audio_mode",
            choices=_AUDIO_MODES.keys(),
            help="Set the audio mode",
        )

        parser.add_argument(
            "--enable_dts",
            action="store_true",
            help="Enable DTS",
        )

        parser.add_argument(
            "--disable_dts",
            action="store_true",
            help="Disable DTS",
        )

        parser.add_argument(
            "--enable_dolby_digital",
            action="store_true",
            help="Enable Dolby Digital",
        )

        parser.add_argument(
            "--disable_dolby_digital",
            action="store_true",
            help="Disable Dolby Digital",
        )

        return parser.parse_args()

    sys.exit(_main(_parse_args()))
