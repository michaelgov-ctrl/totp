const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

pub fn hotp(key: []const u8, counter: u32) u32 {
    // https://www.rfc-editor.org/info/rfc4226/#section-5.3

    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(
        u64,
        &counter_bytes,
        counter,
        .big,
    );

    var hmac = HmacSha1.init(key);
    hmac.update(&counter_bytes);
    var ac: [HmacSha1.mac_length]u8 = undefined;
    hmac.final(&ac);

    const snum = dt(&ac);
    return snum % 1000000;
}

fn dt(mac: *const [Sha1.digest_length]u8) u32 {
    // https://www.rfc-editor.org/info/rfc4226/#section-5.4

    const offset: u4 = @truncate(mac[19]);
    const ret = std.mem.readInt(
        u32,
        mac[offset..][0..4],
        .big,
    );
    return ret & 0x7fffffff;
}

pub fn totp(io: std.Io, b32key: []const u8) u32 {
    // https://www.rfc-editor.org/info/rfc6238/#section-4.2

    const now = std.Io.Timestamp.now(io, .real);
    const t: u32 = @intCast(now.toSeconds());
    const i = 30;

    return hotp(b32key, t / i);
}
