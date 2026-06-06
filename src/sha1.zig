const std = @import("std");

pub const Sha1 = struct {
    // https://www.rfc-editor.org/info/rfc3174/

    pub const block_bytes = 512 / 8;

    const k: [4]u32 = .{
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6,
    };

    h: [5]u32,
    block_buffer: [block_bytes]u8,
    block: std.ArrayList(u8),
    message_len_bytes: usize,

    pub fn initPinned(self: *Sha1) void {
        self.* = .{
            .h = .{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            },
            .block_buffer = undefined,
            .block = .initBuffer(&self.block_buffer),
            .message_len_bytes = 0,
        };
    }

    pub fn update(self: *Sha1, allocator: std.mem.Allocator, data: []const u8) !void {
        var remaining = data;
        while (remaining.len > 0) {
            const push_len = @min(
                block_bytes - self.block.items.len,
                remaining.len,
            );

            try self.block.appendSlice(allocator, remaining[0..push_len]);
            remaining = if (push_len == remaining.len) "" else remaining[push_len..];

            if (self.block.items.len == block_bytes) {
                self.hashBlock();
            }
        }

        self.message_len_bytes += data.len;
    }

    pub fn final(self: *Sha1, allocator: std.mem.Allocator) ![20]u8 {
        if (self.block.items.len == block_bytes) {
            self.hashBlock();
        }

        try self.block.appendBounded(0x80);
        if (self.block.items.len == block_bytes) {
            self.hashBlock();
        }

        const num_zeroes = block_bytes - 8 - self.block.items.len;
        const zeroes = try self.block.addManyAsSlice(allocator, num_zeroes);
        @memset(zeroes, 0);

        var size_buf: [8]u8 = undefined;
        std.mem.writeInt(
            u64,
            &size_buf,
            self.message_len_bytes * 8,
            .big,
        );
        try self.block.appendSlice(allocator, &size_buf);

        self.hashBlock();

        var ret: [20]u8 = undefined;
        for (self.h, 0..) |word, i| {
            std.mem.writeInt(
                u32,
                ret[i * 4 ..][0..4],
                word,
                .big,
            );
        }

        return ret;
    }

    fn hashBlock(self: *Sha1) void {
        std.debug.assert(self.block.items.len == block_bytes);
        const block = self.block.items;

        // page 6

        // Now M(1), M(2), ... , M(n) are processed.  To process M(i), we
        // proceed as follows:

        // a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0)
        //     is the left-most word.
        var w: [80]u32 = undefined; // words
        for (0..16) |i| {
            // parse 4 u8's(1 byte) into one u32
            w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }

        // b. For t = 16 to 79 let
        //     W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
        for (16..80) |t| {
            w[t] = s(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
        }

        // c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
        var a = self.h[0];
        var b = self.h[1];
        var c = self.h[2];
        var d = self.h[3];
        var e = self.h[4];

        // d. For t = 0 to 79 do
        //     TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
        //     E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        for (0..80) |t| {
            // 32-bit wrap addition
            const temp = s(5, a) +%
                f(t, b, c, d) +%
                e +% w[t] +% k[t / 20];

            e = d;
            d = c;
            c = s(30, b);
            b = a;
            a = temp;
        }

        // e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E.
        // 32-bit wrap addition
        self.h[0] = self.h[0] +% a;
        self.h[1] = self.h[1] +% b;
        self.h[2] = self.h[2] +% c;
        self.h[3] = self.h[3] +% d;
        self.h[4] = self.h[4] +% e;

        self.block.clearRetainingCapacity();
    }

    fn s(rot: u32, val: u32) u32 {
        // S^n(X)  =  (X << n) OR (X >> 32-n)
        // rot == n and val == x
        return (val << @intCast(rot)) | (val >> @intCast(32 - rot));
    }

    fn f(t: usize, b: u32, c: u32, d: u32) u32 {
        // f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)
        // f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)
        // f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
        // f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79).
        return switch (t) {
            0...19 => (b & c) | ((~b) & d),
            20...39 => b ^ c ^ d,
            40...59 => (b & c) | (b & d) | (c & d),
            60...79 => b ^ c ^ d,
            else => unreachable,
        };
    }

    pub fn hmac(allocator: std.mem.Allocator, key: []const u8, data: []const u8) ![20]u8 {
        // https://www.rfc-editor.org/info/rfc2104/#section-2

        var k_prime: [Sha1.block_bytes]u8 = @splat(0);

        std.debug.assert(key.len <= Sha1.block_bytes);

        @memcpy(k_prime[0..key.len], key);

        const ipad: u8 = 0x36;
        for (&k_prime) |*b| {
            b.* ^= ipad;
        }

        var inner_hash_computer: Sha1 = undefined;
        inner_hash_computer.initPinned();
        try inner_hash_computer.update(allocator, &k_prime);
        try inner_hash_computer.update(allocator, data);
        const inner_hash = try inner_hash_computer.final(allocator);

        const opad = ipad ^ 0x5c;
        for (&k_prime) |*b| {
            b.* ^= opad;
        }

        var outer_hash_computer: Sha1 = undefined;
        outer_hash_computer.initPinned();
        try outer_hash_computer.update(allocator, &k_prime);
        try outer_hash_computer.update(allocator, &inner_hash);
        const ret = try outer_hash_computer.final(allocator);

        return ret;
    }
};
