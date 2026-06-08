const std = @import("std");
const base32 = @import("base32.zig");
const otp = @import("otp.zig");

// https://www.youtube.com/watch?v=-d2sBd_ZJOk
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) {
        return error.MissingKeyArg;
    }

    const input = args[1];
    const key = try decodeString(allocator, input);

    const totp = otp.totp(io, key);

    var buf: [1024]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &buf);
    const stdout = &writer.interface;

    try stdout.print("{d}\n", .{totp});
    try stdout.flush();
}

fn decodeString(allocator: std.mem.Allocator, src: []const u8) ![]const u8 {
    const size = base32.std_encoding.decodeLen(src.len);

    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);

    return try base32.std_encoding.decode(buf, src);
}
