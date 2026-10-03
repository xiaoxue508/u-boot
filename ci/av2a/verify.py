#!/usr/bin/env python3
"""Structural verification of the packaged AV2A boot image."""
import hashlib
import os
import struct
import sys

from Crypto.Cipher import AES

FIP = 0xc200
BL31_MAGIC = 0x12348765

UUIDS = {
    'BL30': bytes([0x97, 0x66, 0xfd, 0x3d, 0x89, 0xbe, 0xe8, 0x49, 0xae, 0x5d, 0x78, 0xa1, 0x40, 0x60, 0x82, 0x13]),
    'BL301': bytes([0xdd, 0xcc, 0xbb, 0xaa, 0xcd, 0xab, 0xef, 0xef, 0xab, 0xcd, 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd]),
    'BL31': bytes([0x47, 0xd4, 0x08, 0x6d, 0x4c, 0xfe, 0x98, 0x46, 0x9b, 0x95, 0x29, 0x50, 0xcb, 0xbd, 0x5a, 0x00]),
    'BL33': bytes([0xd6, 0xd0, 0xee, 0xa7, 0xfc, 0xea, 0xd5, 0x4b, 0x97, 0x82, 0x99, 0x34, 0xf2, 0x34, 0xb6, 0xe4]),
}
REV = {v: k for k, v in UUIDS.items()}


def decrypt_blob(data, off):
    cb = data[off:off + 256]
    firstblk = struct.unpack_from('<I', cb, 16)[0]
    payloadsz = struct.unpack_from('<I', cb, 28)[0]
    key = cb[64:96]
    iv = cb[96:112]
    has_hdr = struct.unpack_from('<I', data, off + 256)[0] == BL31_MAGIC
    if payloadsz % 512 != 0:
        raise ValueError('payloadsz not aligned at %s' % hex(off))
    ct = data[off + firstblk:off + firstblk + 512] + data[off + 512:off + payloadsz]
    if len(ct) != payloadsz:
        raise ValueError('short ciphertext at %s' % hex(off))
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if has_hdr:
        pt = data[off + 256:off + 512] + pt
    return pt


def main():
    img_path, here = sys.argv[1], sys.argv[2]
    data = open(img_path, 'rb').read(0x1000000)
    hard, soft = [], []

    bl2 = open(os.path.join(here, 'bl2sig.bin'), 'rb').read()
    if len(bl2) != 0xc000:
        hard.append('bl2sig.bin wrong size')
    if data[:0xc000] != bl2:
        diff = next((i for i in range(0xc000) if data[i] != bl2[i]), None)
        soft.append('BL2 region differs from original machine BL2 (first diff @%s, md5=%s)'
                    % (hex(diff) if diff is not None else '?', hashlib.md5(data[:0xc000]).hexdigest()))
    if any(data[0xc000:0xc200]):
        soft.append('[0xc000:0xc200] not zero-padded (tool layout?)')
    if len(data) > 0x800000:
        hard.append('image suspiciously large: %d' % len(data))

    # locate FIP: first amlcblk control block (AMLC at +12 and +252)
    def is_cb(p):
        return (p + 256 <= len(data)
                and data[p + 12:p + 16] == b'AMLC'
                and data[p + 252:p + 256] == b'AMLC')

    cands = [p for p in range(0, 0x20000) if is_cb(p)]
    print('AMLC control blocks in first 128K:', [hex(p) for p in cands])
    print('bytes @0xc000:', data[0xc000:0xc020].hex())
    print('bytes @0xc200:', data[0xc200:0xc220].hex())
    if not cands:
        hard.append('no AMLC FIP header found in first 128K')
        print('FAIL: ' + '; '.join(hard))
        return 1
    FIP = next((p for p in cands if p >= 0xc000), cands[0])
    print('FIP base = %s' % hex(FIP))

    toc = decrypt_blob(data, FIP)
    magic, serial = struct.unpack_from('<II', toc, 0)
    print('ToC magic=0x%08x serial=0x%08x' % (magic, serial))
    if magic != 0xAA640001:
        hard.append('unexpected ToC magic')

    entries = {}
    for i in range(16):
        eoff = 16 + i * 40
        uu = toc[eoff:eoff + 16]
        if uu == b'\xff' * 16:
            break
        if uu == b'\x00' * 16:
            continue
        off, size = struct.unpack_from('<QQ', toc, eoff + 16)
        name = REV.get(uu, 'UNKNOWN-' + uu.hex()[:12])
        entries[name] = (off, size)
        print('entry %-10s fip+0x%x size=0x%x' % (name, off, size))

    for need in ('BL30', 'BL31', 'BL33'):
        if need not in entries:
            hard.append('missing ToC entry ' + need)
    if 'BL301' not in entries:
        soft.append('no separate BL301 entry (merged into BL30?)')

    def payload(name):
        off, size = entries[name]
        for base in (FIP, 0xc000, 0):
            cand = base + off
            if data[cand + 12:cand + 16] == b'AMLC' and data[cand + 252:cand + 256] == b'AMLC':
                return decrypt_blob(data, cand)
        hard.append('no AMLC control block for ' + name)
        return None

    bl30_ref = open(os.path.join(here, 'bl30.bin'), 'rb').read()
    bl301_ref = open(os.path.join(here, 'bl301.bin'), 'rb').read()
    bl31_ref = open(os.path.join(here, 'bl31.img'), 'rb').read()
    bl33_ref = open(os.path.join(here, 'out', 'u-boot-bl33.bin'), 'rb').read()

    p = payload('BL30')
    if p is not None:
        if p[:len(bl30_ref)] == bl30_ref:
            print('BL30 payload == original machine bl30.bin (%d bytes)' % len(bl30_ref))
        else:
            hard.append('BL30 payload mismatch')
        if 'BL301' in entries:
            q = payload('BL301')
            if q is not None and q[:len(bl301_ref)] != bl301_ref:
                hard.append('BL301 payload mismatch')
            elif q is not None:
                print('BL301 payload == original machine bl301.bin')
        else:
            if len(p) >= 0xa000 + len(bl301_ref) and p[0xa000:0xa000 + len(bl301_ref)] == bl301_ref:
                print('bl301 found merged at offset 0xa000 inside BL30 payload')

    p = payload('BL31')
    if p is not None:
        if p[:len(bl31_ref)] == bl31_ref:
            print('BL31 payload == original machine bl31.img (%d bytes)' % len(bl31_ref))
        else:
            hard.append('BL31 payload mismatch')

    p = payload('BL33')
    if p is not None:
        if p == bl33_ref:
            print('BL33 payload == built mainline u-boot (%d bytes)' % len(bl33_ref))
        elif p[:len(bl33_ref)] == bl33_ref:
            print('BL33 payload == built mainline u-boot (padded, %d -> %d)' % (len(bl33_ref), len(p)))
        else:
            hard.append('BL33 payload mismatch')
        if b'U-Boot 20' not in p[:0x2000] and b'U-Boot 20' not in p:
            soft.append('no U-Boot version string in BL33')

    print('image size: %d bytes  md5: %s' % (len(data), hashlib.md5(data).hexdigest()))
    for w in soft:
        print('WARN: ' + w)
    if hard:
        print('FAIL:')
        for e in hard:
            print('  - ' + e)
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
