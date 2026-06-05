const std = @import("std");

const Sha1 = @import("sha1.zig").Sha1;

fn hmacSha1(gpa: std.mem.Allocator, key: []const u8, data: []const u8) ![20]u8 {
    // https://www.rfc-editor.org/info/rfc2104/#section-2

    var k_prime: [Sha1.block_bytes]u8 = @splat(0);

    // Hash the key dummy
    std.debug.assert(key.len <= Sha1.block_bytes);

    @memcpy(k_prime[0..key.len], key);

    const ipad: u8 = 0x36;
    for (&k_prime) |*b| {
        b.* ^= ipad;
    }

    var inner_hash_computer: Sha1 = undefined;
    inner_hash_computer.initPinned();
    try inner_hash_computer.update(gpa, &k_prime);
    try inner_hash_computer.update(gpa, data);
    const inner_hash = try inner_hash_computer.final(gpa);

    const opad = ipad ^ 0x5c;
    for (&k_prime) |*b| {
        b.* ^= opad;
    }

    var outer_hash_computer: Sha1 = undefined;
    outer_hash_computer.initPinned();
    try outer_hash_computer.update(gpa, &k_prime);
    try outer_hash_computer.update(gpa, &inner_hash);
    const ret = try outer_hash_computer.final(gpa);

    return ret;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();

    // const args = try init.minimal.args.toSlice(gpa);
    // if (args.len < 2) {
    //     return error.MissingStringArg;
    // }

    // const input = args[1];

    // var sha: Sha1 = undefined;
    // sha.initPinned();
    // try sha.update(gpa, input);
    // const hash = try sha.final(gpa);

    // std.debug.print("{x}\n", .{hash});

    const hash = try hmacSha1(gpa, "key", "asdf");
    std.debug.print("{x}\n", .{hash});
}

test {
    std.testing.refAllDecls(@This());

    _ = Sha1;
}
