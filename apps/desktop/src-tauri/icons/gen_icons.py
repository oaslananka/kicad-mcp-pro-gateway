import struct, zlib, os

def make_png(width, height, rgba):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        for x in range(width):
            raw.extend(rgba)
    idat = zlib.compress(bytes(raw), 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")

def make_ico(png_entries):
    # png_entries: list of (width, height, png_bytes)
    count = len(png_entries)
    header = struct.pack("<HHH", 0, 1, count)
    dir_entries = b""
    data_blob = b""
    offset = 6 + 16 * count
    for w, h, data in png_entries:
        w_b = w if w < 256 else 0
        h_b = h if h < 256 else 0
        dir_entries += struct.pack("<BBBBHHII", w_b, h_b, 0, 0, 1, 32, len(data), offset)
        data_blob += data
        offset += len(data)
    return header + dir_entries + data_blob

rgba = bytes([0x1E, 0x3A, 0x5F, 0xFF])  # solid dark blue-gray, opaque

out_dir = os.path.dirname(os.path.abspath(__file__))
sizes = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "icon.png": 512,
}
pngs = {}
for name, size in sizes.items():
    data = make_png(size, size, rgba)
    pngs[name] = (size, data)
    with open(os.path.join(out_dir, name), "wb") as f:
        f.write(data)

ico_entries = [(pngs["32x32.png"][0], pngs["32x32.png"][0], pngs["32x32.png"][1]),
               (pngs["128x128.png"][0], pngs["128x128.png"][0], pngs["128x128.png"][1])]
with open(os.path.join(out_dir, "icon.ico"), "wb") as f:
    f.write(make_ico(ico_entries))

print("icons written to", out_dir)
