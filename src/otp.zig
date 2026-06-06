const std = @import("std");

const Sha1 = @import("sha1.zig").Sha1;

pub fn hotp(allocator: std.mem.Allocator, key: []const u8, counter: u32) !u32 {
    // https://www.rfc-editor.org/info/rfc4226/#section-5.3

    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(
        u64,
        &counter_bytes,
        counter,
        .big,
    );

    const hmac = try Sha1.hmac(
        allocator,
        key,
        &counter_bytes,
    );

    const snum = dt(&hmac);
    return snum % 1000000;
}

fn dt(mac: *const [20]u8) u32 {
    // https://www.rfc-editor.org/info/rfc4226/#section-5.4

    const offset: u4 = @truncate(mac[19]);
    const ret = std.mem.readInt(
        u32,
        mac[offset..][0..4],
        .big,
    );
    return ret & 0x7fffffff;
}

pub fn totp(allocator: std.mem.Allocator, io: std.Io, b32key: []const u8) !u32 {
    // https://www.rfc-editor.org/info/rfc6238/#section-4.2

    const now = std.Io.Timestamp.now(io, .real);
    const t: u32 = @intCast(now.toSeconds());
    const i = 30;

    return try hotp(allocator, b32key, t / i);
}
