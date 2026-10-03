# ci/av2a — S905L3B AV2A custom boot chain

Original machine boot chain (decrypted from `emmc_full.img` backup):

| file        | origin                                | md5                              |
|-------------|---------------------------------------|----------------------------------|
| bl2sig.bin  | emmc_full.img[0:0xc000] (signed BL2+acs) | 4b413d3682b08db2d4f3103f92675b61 |
| bl30.bin    | FIP BL30 section (decrypted)          | 6eb3f931aa9713de3bdcbfd030ac7d03 |
| bl301.bin   | FIP BL301 section (decrypted)         | 23769fd31ad92d7d9dfd8ebc44314233 |
| bl31.img    | FIP BL31 section (decrypted)          | d6ff6bc874652dc00701626ec24213bb |

The only replaced component is **BL33**: mainline u-boot (`unifreq/u-boot`,
p212_defconfig) with the p212 dts memory node patched **2GB -> 1GB**
(`meson-gxl-s905x-p212.dtsi`) — the unpatched 2GB node makes u-boot relocate
into non-existent DRAM on this 1GB box and hang (root cause of earlier failed
mainline candidates).

Outputs (Actions artifact `u-boot-av2a`):

* `u-boot-bl33.bin` — plain mainline u-boot, TEXT_BASE=0x01000000, test via
  `u-boot.emmc` + `go 0x1000000` (ophub overload mechanism, USB stick = easy rollback).
* `u-boot-full.bin` — complete image (original BL2+BL30+BL301+BL31 + new BL33),
  for permanent flash later; verified by `verify.py`.
