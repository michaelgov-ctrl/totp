const std = @import("std");

// look into std.crypto.nacl.SecretBox

pub fn encryptToFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    password: []const u8,
    plaintext: []const u8,
) !void {
    // encrypt plaintext to ciphertext
    _ = allocator;
    _ = password;
    const ciphertext = plaintext;

    var file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
    });
    defer file.close(io);

    try file.writeStreamingAll(io, ciphertext);
}

pub fn decryptFromFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    key: []const u8,
) ![]u8 {
    _ = key;

    const content = try std.Io.Dir.readFileAlloc(
        std.Io.Dir.cwd(),
        io,
        path,
        allocator,
        .unlimited,
    );

    // decrypt and return content

    return content;
}
