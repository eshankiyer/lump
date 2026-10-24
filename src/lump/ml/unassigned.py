"""Code points unassigned in Unicode 14.0 (the tables of Python 3.11).

The featuriser maps them to U+FFFD before normalising. Each runtime's NFKC and
lower-casing follow its own Unicode version (Python 3.11: 14.0, 3.13: 15.1,
Node 22 and current Chrome: 16 or later), and characters added after 14.0 fold
or lower-case on one side only, so the browser and the gateway would compute
different features for the same text. Mappings of characters assigned by 14.0
are stable, so masking the rest makes every supported runtime agree.

Generated from the Unicode Character Database ``DerivedAge.txt`` (15.1.0,
sha256 04e16379344bdb9973cdb6f6bf0a5dd66f7cd41b014cd9f79d848768ae757256):
``python -m lump.ml.unassigned DerivedAge.txt``. Hex ranges, comma-separated;
``extension/ml.js`` embeds the same string (a test keeps them identical).
"""

from __future__ import annotations

import re
import sys

BASELINE = "14.0"
RANGES = (
    "378-379,380-383,38b,38d,3a2,530,557-558,58b-58c,590,5c8-5cf,5eb-5ee,5f5-5ff,70e,74b-74c,7b2-7bf,7fb-"
    "7fc,82e-82f,83f,85c-85d,85f,86b-86f,88f,892-897,984,98d-98e,991-992,9a9,9b1,9b3-9b5,9ba-9bb,9c5-9c6,"
    "9c9-9ca,9cf-9d6,9d8-9db,9de,9e4-9e5,9ff-a00,a04,a0b-a0e,a11-a12,a29,a31,a34,a37,a3a-a3b,a3d,a43-a46,"
    "a49-a4a,a4e-a50,a52-a58,a5d,a5f-a65,a77-a80,a84,a8e,a92,aa9,ab1,ab4,aba-abb,ac6,aca,ace-acf,ad1-adf,"
    "ae4-ae5,af2-af8,b00,b04,b0d-b0e,b11-b12,b29,b31,b34,b3a-b3b,b45-b46,b49-b4a,b4e-b54,b58-b5b,b5e,b64-"
    "b65,b78-b81,b84,b8b-b8d,b91,b96-b98,b9b,b9d,ba0-ba2,ba5-ba7,bab-bad,bba-bbd,bc3-bc5,bc9,bce-bcf,bd1-"
    "bd6,bd8-be5,bfb-bff,c0d,c11,c29,c3a-c3b,c45,c49,c4e-c54,c57,c5b-c5c,c5e-c5f,c64-c65,c70-c76,c8d,c91,"
    "ca9,cb4,cba-cbb,cc5,cc9,cce-cd4,cd7-cdc,cdf,ce4-ce5,cf0,cf3-cff,d0d,d11,d45,d49,d50-d53,d64-d65,d80,"
    "d84,d97-d99,db2,dbc,dbe-dbf,dc7-dc9,dcb-dce,dd5,dd7,de0-de5,df0-df1,df5-e00,e3b-e3e,e5c-e80,e83,e85,"
    "e8b,ea4,ea6,ebe-ebf,ec5,ec7,ece-ecf,eda-edb,ee0-eff,f48,f6d-f70,f98,fbd,fcd,fdb-fff,10c6,10c8-10cc,1"
    "0ce-10cf,1249,124e-124f,1257,1259,125e-125f,1289,128e-128f,12b1,12b6-12b7,12bf,12c1,12c6-12c7,12d7,1"
    "311,1316-1317,135b-135c,137d-137f,139a-139f,13f6-13f7,13fe-13ff,169d-169f,16f9-16ff,1716-171e,1737-1"
    "73f,1754-175f,176d,1771,1774-177f,17de-17df,17ea-17ef,17fa-17ff,181a-181f,1879-187f,18ab-18af,18f6-1"
    "8ff,191f,192c-192f,193c-193f,1941-1943,196e-196f,1975-197f,19ac-19af,19ca-19cf,19db-19dd,1a1c-1a1d,1"
    "a5f,1a7d-1a7e,1a8a-1a8f,1a9a-1a9f,1aae-1aaf,1acf-1aff,1b4d-1b4f,1b7f,1bf4-1bfb,1c38-1c3a,1c4a-1c4c,1"
    "c89-1c8f,1cbb-1cbc,1cc8-1ccf,1cfb-1cff,1f16-1f17,1f1e-1f1f,1f46-1f47,1f4e-1f4f,1f58,1f5a,1f5c,1f5e,1"
    "f7e-1f7f,1fb5,1fc5,1fd4-1fd5,1fdc,1ff0-1ff1,1ff5,1fff,2065,2072-2073,208f,209d-209f,20c1-20cf,20f1-2"
    "0ff,218c-218f,2427-243f,244b-245f,2b74-2b75,2b96,2cf4-2cf8,2d26,2d28-2d2c,2d2e-2d2f,2d68-2d6e,2d71-2"
    "d7e,2d97-2d9f,2da7,2daf,2db7,2dbf,2dc7,2dcf,2dd7,2ddf,2e5e-2e7f,2e9a,2ef4-2eff,2fd6-2fef,2ffc-2fff,3"
    "040,3097-3098,3100-3104,3130,318f,31e4-31ef,321f,a48d-a48f,a4c7-a4cf,a62c-a63f,a6f8-a6ff,a7cb-a7cf,a"
    "7d2,a7d4,a7da-a7f1,a82d-a82f,a83a-a83f,a878-a87f,a8c6-a8cd,a8da-a8df,a954-a95e,a97d-a97f,a9ce,a9da-a"
    "9dd,a9ff,aa37-aa3f,aa4e-aa4f,aa5a-aa5b,aac3-aada,aaf7-ab00,ab07-ab08,ab0f-ab10,ab17-ab1f,ab27,ab2f,a"
    "b6c-ab6f,abee-abef,abfa-abff,d7a4-d7af,d7c7-d7ca,d7fc-d7ff,fa6e-fa6f,fada-faff,fb07-fb12,fb18-fb1c,f"
    "b37,fb3d,fb3f,fb42,fb45,fbc3-fbd2,fd90-fd91,fdc8-fdce,fe1a-fe1f,fe53,fe67,fe6c-fe6f,fe75,fefd-fefe,f"
    "f00,ffbf-ffc1,ffc8-ffc9,ffd0-ffd1,ffd8-ffd9,ffdd-ffdf,ffe7,ffef-fff8,1000c,10027,1003b,1003e,1004e-1"
    "004f,1005e-1007f,100fb-100ff,10103-10106,10134-10136,1018f,1019d-1019f,101a1-101cf,101fe-1027f,1029d"
    "-1029f,102d1-102df,102fc-102ff,10324-1032c,1034b-1034f,1037b-1037f,1039e,103c4-103c7,103d6-103ff,104"
    "9e-1049f,104aa-104af,104d4-104d7,104fc-104ff,10528-1052f,10564-1056e,1057b,1058b,10593,10596,105a2,1"
    "05b2,105ba,105bd-105ff,10737-1073f,10756-1075f,10768-1077f,10786,107b1,107bb-107ff,10806-10807,10809"
    ",10836,10839-1083b,1083d-1083e,10856,1089f-108a6,108b0-108df,108f3,108f6-108fa,1091c-1091e,1093a-109"
    "3e,10940-1097f,109b8-109bb,109d0-109d1,10a04,10a07-10a0b,10a14,10a18,10a36-10a37,10a3b-10a3e,10a49-1"
    "0a4f,10a59-10a5f,10aa0-10abf,10ae7-10aea,10af7-10aff,10b36-10b38,10b56-10b57,10b73-10b77,10b92-10b98"
    ",10b9d-10ba8,10bb0-10bff,10c49-10c7f,10cb3-10cbf,10cf3-10cf9,10d28-10d2f,10d3a-10e5f,10e7f,10eaa,10e"
    "ae-10eaf,10eb2-10eff,10f28-10f2f,10f5a-10f6f,10f8a-10faf,10fcc-10fdf,10ff7-10fff,1104e-11051,11076-1"
    "107e,110c3-110cc,110ce-110cf,110e9-110ef,110fa-110ff,11135,11148-1114f,11177-1117f,111e0,111f5-111ff"
    ",11212,1123f-1127f,11287,11289,1128e,1129e,112aa-112af,112eb-112ef,112fa-112ff,11304,1130d-1130e,113"
    "11-11312,11329,11331,11334,1133a,11345-11346,11349-1134a,1134e-1134f,11351-11356,11358-1135c,11364-1"
    "1365,1136d-1136f,11375-113ff,1145c,11462-1147f,114c8-114cf,114da-1157f,115b6-115b7,115de-115ff,11645"
    "-1164f,1165a-1165f,1166d-1167f,116ba-116bf,116ca-116ff,1171b-1171c,1172c-1172f,11747-117ff,1183c-118"
    "9f,118f3-118fe,11907-11908,1190a-1190b,11914,11917,11936,11939-1193a,11947-1194f,1195a-1199f,119a8-1"
    "19a9,119d8-119d9,119e5-119ff,11a48-11a4f,11aa3-11aaf,11af9-11bff,11c09,11c37,11c46-11c4f,11c6d-11c6f"
    ",11c90-11c91,11ca8,11cb7-11cff,11d07,11d0a,11d37-11d39,11d3b,11d3e,11d48-11d4f,11d5a-11d5f,11d66,11d"
    "69,11d8f,11d92,11d99-11d9f,11daa-11edf,11ef9-11faf,11fb1-11fbf,11ff2-11ffe,1239a-123ff,1246f,12475-1"
    "247f,12544-12f8f,12ff3-12fff,1342f,13439-143ff,14647-167ff,16a39-16a3f,16a5f,16a6a-16a6d,16abf,16aca"
    "-16acf,16aee-16aef,16af6-16aff,16b46-16b4f,16b5a,16b62,16b78-16b7c,16b90-16e3f,16e9b-16eff,16f4b-16f"
    "4e,16f88-16f8e,16fa0-16fdf,16fe5-16fef,16ff2-16fff,187f8-187ff,18cd6-18cff,18d09-1afef,1aff4,1affc,1"
    "afff,1b123-1b14f,1b153-1b163,1b168-1b16f,1b2fc-1bbff,1bc6b-1bc6f,1bc7d-1bc7f,1bc89-1bc8f,1bc9a-1bc9b"
    ",1bca4-1ceff,1cf2e-1cf2f,1cf47-1cf4f,1cfc4-1cfff,1d0f6-1d0ff,1d127-1d128,1d1eb-1d1ff,1d246-1d2df,1d2"
    "f4-1d2ff,1d357-1d35f,1d379-1d3ff,1d455,1d49d,1d4a0-1d4a1,1d4a3-1d4a4,1d4a7-1d4a8,1d4ad,1d4ba,1d4bc,1"
    "d4c4,1d506,1d50b-1d50c,1d515,1d51d,1d53a,1d53f,1d545,1d547-1d549,1d551,1d6a6-1d6a7,1d7cc-1d7cd,1da8c"
    "-1da9a,1daa0,1dab0-1deff,1df1f-1dfff,1e007,1e019-1e01a,1e022,1e025,1e02b-1e0ff,1e12d-1e12f,1e13e-1e1"
    "3f,1e14a-1e14d,1e150-1e28f,1e2af-1e2bf,1e2fa-1e2fe,1e300-1e7df,1e7e7,1e7ec,1e7ef,1e7ff,1e8c5-1e8c6,1"
    "e8d7-1e8ff,1e94c-1e94f,1e95a-1e95d,1e960-1ec70,1ecb5-1ed00,1ed3e-1edff,1ee04,1ee20,1ee23,1ee25-1ee26"
    ",1ee28,1ee33,1ee38,1ee3a,1ee3c-1ee41,1ee43-1ee46,1ee48,1ee4a,1ee4c,1ee50,1ee53,1ee55-1ee56,1ee58,1ee"
    "5a,1ee5c,1ee5e,1ee60,1ee63,1ee65-1ee66,1ee6b,1ee73,1ee78,1ee7d,1ee7f,1ee8a,1ee9c-1eea0,1eea4,1eeaa,1"
    "eebc-1eeef,1eef2-1efff,1f02c-1f02f,1f094-1f09f,1f0af-1f0b0,1f0c0,1f0d0,1f0f6-1f0ff,1f1ae-1f1e5,1f203"
    "-1f20f,1f23c-1f23f,1f249-1f24f,1f252-1f25f,1f266-1f2ff,1f6d8-1f6dc,1f6ed-1f6ef,1f6fd-1f6ff,1f774-1f7"
    "7f,1f7d9-1f7df,1f7ec-1f7ef,1f7f1-1f7ff,1f80c-1f80f,1f848-1f84f,1f85a-1f85f,1f888-1f88f,1f8ae-1f8af,1"
    "f8b2-1f8ff,1fa54-1fa5f,1fa6e-1fa6f,1fa75-1fa77,1fa7d-1fa7f,1fa87-1fa8f,1faad-1faaf,1fabb-1fabf,1fac6"
    "-1facf,1fada-1fadf,1fae8-1faef,1faf7-1faff,1fb93,1fbcb-1fbef,1fbfa-1fffd,2a6e0-2a6ff,2b739-2b73f,2b8"
    "1e-2b81f,2cea2-2ceaf,2ebe1-2f7ff,2fa1e-2fffd,3134b-3fffd,40000-4fffd,50000-5fffd,60000-6fffd,70000-7"
    "fffd,80000-8fffd,90000-9fffd,a0000-afffd,b0000-bfffd,c0000-cfffd,d0000-dfffd,e0000,e0002-e001f,e0080"
    "-e00ff,e01f0-efffd"
)


def ranges(encoded: str = RANGES) -> list[tuple[int, int]]:
    out = []
    for part in encoded.split(","):
        a, _, b = part.partition("-")
        out.append((int(a, 16), int(b or a, 16)))
    return out


def pattern() -> re.Pattern[str]:
    return re.compile("[" + "".join(f"\\U{a:08x}-\\U{b:08x}" for a, b in ranges()) + "]")


def generate(derived_age_path: str, baseline: tuple[int, int] = (14, 0)) -> str:
    """Rebuild :data:`RANGES` from a ``DerivedAge.txt`` file."""

    assigned = bytearray(0x110000)
    line_re = re.compile(r"^([0-9A-F]+)(?:\.\.([0-9A-F]+))?\s*;\s*([0-9]+)\.([0-9]+)")
    with open(derived_age_path, encoding="utf-8") as fh:
        for line in fh:
            m = line_re.match(line)
            if m and (int(m.group(3)), int(m.group(4))) <= baseline:
                a = int(m.group(1), 16)
                b = int(m.group(2) or m.group(1), 16)
                assigned[a : b + 1] = b"\x01" * (b - a + 1)
    out, start = [], None
    for cp in range(0x110000):
        if not assigned[cp] and start is None:
            start = cp
        elif assigned[cp] and start is not None:
            out.append((start, cp - 1))
            start = None
    if start is not None:
        out.append((start, 0x10FFFF))
    return ",".join(f"{a:x}-{b:x}" if a != b else f"{a:x}" for a, b in out)


if __name__ == "__main__":
    print(generate(sys.argv[1]))
