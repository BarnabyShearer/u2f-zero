#! /usr/bin/env python3
"""
Programs a blank U2F-Zero key via Bootloader
"""

import argparse
import contextlib
from subprocess import call
import datetime
import time
import random
import array
import binascii
import hashlib

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import hid
import efm8
import efm8.u2fzero
from crccheck.crc import CrcArc

U2F_CONFIG_GET_SERIAL_NUM = 0x80
U2F_CONFIG_IS_BUILD = 0x81
U2F_CONFIG_LOCK = 0x83
U2F_CONFIG_LOAD_TRANS_KEY = 0x85
U2F_CONFIG_LOAD_WRITE_KEY = 0x86
U2F_CONFIG_LOAD_ATTEST_KEY = 0x87

# Factory config for ATEC508A
CONFIG = (
    b"\x01\x23\x6d\x10\x00\x00\x50\x00\xd7\x2c\xa5\x71\xee\xc0\x85\x00"
    b"\xc0\x00\x55\x00\x83\x71\x81\x01\x83\x71\xC1\x01\x83\x71\x83\x71"
    b"\x83\x71\xC1\x71\x01\x01\x83\x71\x83\x71\xC1\x71\x83\x71\x83\x71"
    b"\x83\x71\x83\x71\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff"
    b"\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    b"\xff\xff\xff\xff\x00\x00\x55\x55\xff\xff\x00\x00\x00\x00\x00\x00"
    b"\x13\x00\x3C\x00\x13\x00\x3C\x00\x13\x00\x3C\x00\x13\x00\x3C\x00"
    b"\x3c\x00\x3C\x00\x13\x00\x3C\x00\x13\x00\x3C\x00\x13\x00\x33\x00"
)

class CrcATECC(CrcArc):
    _reflect_output = False

def get_write_mask(key):
    m = hashlib.new('sha256')
    m.update(bytes(key) + b'\x15\x02\x01\x00\xee\x01\x23' + (b'\x00'*57))
    h1 = m.digest()
    m = hashlib.new('sha256')
    m.update(h1)
    h2 = m.digest()
    return h1 + h2[:4]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-p", "--product", help="USB Product ID of device to program", default="EACB")
    parser.add_argument("-s", "--serial", help="Serial number of device to program")
    args = parser.parse_args()

    # Generate a prime256r1 EC key pair
    key = ec.generate_private_key(
        curve=ec.SECP256R1(),
        backend=default_backend()
    )
    # Generate a 10-year self-signed X509 cert with that key
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"U2F-Zero"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10*365)
    ).sign(key, hashes.SHA256(), default_backend())

    # Enter bootloader (If device was already programed)
    # May need to short pin 12 (corner near silkscreen 'm') to GND
    try:
        efm8.u2fzero.reset(0x10C4, 0x8ACF, args.serial)
    except:
        pass

    # Build setup firmware for loading new key/cert
    call('cd firmware; make setup/FIRMWARE.HEX', shell=True)

    # Flash setup firmware
    efm8.flash(
        0x10C4,
        int(args.product, 16),
        args.serial,
        efm8.to_frames(
            efm8.read_intel_hex(
                'firmware/setup/FIRMWARE.HEX'
            )
        )
    )

    time.sleep(1)

    with contextlib.closing(hid.device()) as dev:
        dev.open(0x10C4, 0x8ACF)

        # Check setup firmware is responding
        dev.write([0, U2F_CONFIG_IS_BUILD])
        data = dev.read(64, 1000)
        if len(data) < 2 or data[1] != 1:
            raise Exception("Device not ready")
        time.sleep(0.250)

        # Read ATEC508A serial number
        dev.write([0, U2F_CONFIG_GET_SERIAL_NUM])
        data = dev.read(64, 1000)
        if len(data) < 2 or data[0] != U2F_CONFIG_GET_SERIAL_NUM:
            raise Exception("Get config error")
        serial = array.array('B', data[2:2 + data[1]]).tostring()
        time.sleep(0.250)

        # Lock config (irreversible but needed before we can write keys)
        # Needs a CRC16 of the config and serial number.
        config = serial + CONFIG[len(serial):]
        dev.write([0, U2F_CONFIG_LOCK] + list(CrcATECC.calcbytes(config)))
        data = dev.read(64, 1000)
        if len(data) < 2 or data[1] != 1:
            raise Exception("Locking error")

        # Write a random key for further communications
        wkey = [random.randint(0, 255) for x in range(0,32)]
        dev.write([0, U2F_CONFIG_LOAD_TRANS_KEY] + wkey)
        data = dev.read(64, 10000)
        if len(data) == 0 or data[1] != 1:
            raise Exception("Faild writing master key")

        # Set that key for signing future commands
        wkey = get_write_mask(wkey)
        dev.write([0, U2F_CONFIG_LOAD_WRITE_KEY] + list(wkey))
        data = dev.read(64, 1000)
        if len(data) == 0 or data[1] != 1:
            raise Exception('failed loading write key')

        # Write the private EC key we generated
        attestkey = key.private_numbers().private_value.to_bytes(32, byteorder='big')
        dev.write([0, U2F_CONFIG_LOAD_ATTEST_KEY] + list(attestkey))
        data = dev.read(64, 1000)
        if len(data) == 0 or data[1] != 1:
            raise Exception('failed loading attestation key')

    # Generate a random key for reading
    rkey = [random.randint(0,255) & 0xff for x in range(0,32)]
    # Ready that key for signing
    rkey = get_write_mask(rkey)

    # Write Cert and read/write keys to cert.c to include in firmware
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    with open("firmware/src/cert.c", "w") as src:
        src.write("""// generated
#include <stdint.h>

code uint8_t __attest[] = """)
        for line in range(0, len(der), 20):
            src.write('"%s"' % "".join(['\\x%02x' % c for c in der[line:line+20]]))
        src.write(""";
const uint16_t __attest_size = sizeof(__attest)-1;

code uint8_t WMASK[] = "%s";
code uint8_t RMASK[] = "%s";
""" % (
            "".join(['\\x%02x' % c for c in wkey]),
            "".join(['\\x%02x' % c for c in rkey])
        ))

    # Enter bootloader
    efm8.u2fzero.reset(0x10C4, 0x8ACF, args.serial)

    # Build main firmware
    call('cd firmware; make build/FIRMWARE.HEX', shell=True)

    # Flash setup firmware
    efm8.flash(
        0x10C4,
        int(args.product, 16),
        args.serial,
        efm8.to_frames(
            efm8.read_intel_hex(
                'firmware/build/FIRMWARE.HEX'
            )
        )
    )

if __name__ == "__main__":
    main()
