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


def _main(args):
    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)

    eeprom = xk.EEPROM()
    eeprom.read_from_bin_file(os.path.realpath(os.path.expanduser(args.eeprom_file)))
    eeprom.log_info()

    encrypted = eeprom.encrypt()


if __name__ == "__main__":

    def _parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "eeprom_file",
            help="The EEPROM file to operate on.",
        )

        parser.add_argument(
            "-v",
            "--verbose",
            help="Enable verbose debug output.",
            action="store_true",
        )

        return parser.parse_args()

    sys.exit(_main(_parse_args()))
