import pyotp
import base64

secret = 'I65VU7K5ZQL7WB4E'

# in zig
# const key: []const u8 = &.{ 0x47, 0xbb, 0x5a, 0x7d, 0x5d, 0xcc, 0x17, 0xfb, 0x07, 0x84 };
print(''.join(format(x, '02x') for x in base64.b32decode(secret)))

totp = pyotp.TOTP(secret)
print(totp.now())