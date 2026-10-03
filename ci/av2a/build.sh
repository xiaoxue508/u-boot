#!/bin/bash
# Package a boot image for S905L3B AV2A:
#   original machine BL2 (bl2sig.bin, byte-exact from emmc backup)
#   original machine BL30/BL301/BL31 (decrypted from FIP)
#   freshly built mainline u-boot as BL33
#
# usage: build.sh <amlogic-boot-fip/p212 dir> <u-boot build dir>
set -euo pipefail

FIPDIR=${1:?usage: build.sh <fip/p212 dir> <u-boot dir>}
UBOOTDIR=${2:?}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/out"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

AML="$FIPDIR/aml_encrypt_gxl"
test -f "$AML"
chmod +x "$AML" 2>/dev/null || true
test -f "$UBOOTDIR/u-boot.bin"
test -f "$OUT/u-boot-bl33.bin"

# bl30 + bl301 merged with zero-padding (amlogic-boot-fip gxl.inc flow)
bash "$HERE/blx_fix.sh" "$HERE/bl30.bin" "$TMP/z1" "$TMP/bl30_pad.bin" \
     "$HERE/bl301.bin" "$TMP/z2" "$TMP/bl30_new.bin" bl30

# aml_encrypt_gxl --bl3enc skips input bytes [0x100:0x200] when the input
# starts with the BL31 header magic: it emits the first 0x100 literally and
# encrypts from offset 0x200. The original machine FIP was packed with the
# same convention (its bl31 payload plaintext is bl31.img[0x100:]), so insert
# a 0x100 filler after the header to keep the entry stub at 0x100 inside the
# encrypted payload. This reproduces the original machine BL31 entry byte for
# byte (literal header + ciphertext of bl31.img[0x100:], payloadsz 0x19400).
{
    dd if="$HERE/bl31.img" bs=256 count=1 status=none
    dd if=/dev/zero       bs=256 count=1 status=none
    dd if="$HERE/bl31.img" bs=256 skip=1 status=none
} > "$TMP/bl31_padded.img"

"$AML" --bl3enc --input "$TMP/bl30_new.bin"    --output "$TMP/bl30_new.bin.enc"
"$AML" --bl3enc --input "$TMP/bl31_padded.img" --output "$TMP/bl31.img.enc"
"$AML" --bl3enc --input "$OUT/u-boot-bl33.bin" --output "$TMP/bl33.bin.enc"

"$AML" --bootmk --output "$OUT/u-boot-full.bin" \
    --bl2 "$HERE/bl2sig.bin" \
    --bl30 "$TMP/bl30_new.bin.enc" \
    --bl31 "$TMP/bl31.img.enc" \
    --bl33 "$TMP/bl33.bin.enc"

echo "== packaged: =="
ls -la "$OUT"

echo "== verify =="
python3 "$HERE/verify.py" "$OUT/u-boot-full.bin" "$HERE"
