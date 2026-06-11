const std = @import("std");
const base32 = @import("base32.zig");
const otp = @import("otp.zig");
const store = @import("store.zig");
const term = @import("terminal.zig");

// https://www.youtube.com/watch?v=-d2sBd_ZJOk
// pub fn main(init: std.process.Init) !void {
//     const allocator = init.arena.allocator();
//     const io = init.io;

//     const args = try init.minimal.args.toSlice(allocator);
//     if (args.len < 2) {
//         return error.MissingKeyArg;
//     }

//     const input = args[1];
//     const key = try decodeString(allocator, input);

//     const totp = otp.totp(io, key);

//     var buf: [1024]u8 = undefined;
//     var writer = std.Io.File.stdout().writer(io, &buf);
//     const stdout = &writer.interface;

//     try stdout.print("{d}\n", .{totp});
//     try stdout.flush();
// }

// fn decodeString(allocator: std.mem.Allocator, src: []const u8) ![]const u8 {
//     const size = base32.std_encoding.decodeLen(src.len);

//     const buf = try allocator.alloc(u8, size);
//     errdefer allocator.free(buf);

//     return try base32.std_encoding.decode(buf, src);
// }

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stdin_buf: [1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(io, &stdin_buf);
    const stdin = &stdin_reader.interface;

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    const password = try term.promptSecret("enter password: ", stdin, stdout);

    try stdout.print("secret: {s}\n", .{password});
    try stdout.flush();

    const filename = "ael.json";

    var in = store.AppEntryList.init();
    defer in.deinit(allocator);

    in.decryptFromFile(
        allocator,
        io,
        filename,
        password,
    ) catch {
        // maybe don't care if this fails, yes the file could later be overwritten..
    };

    for (in.list.items) |entry| {
        std.debug.print("in - name: {s}, key: {s}\n", .{ entry.name, entry.key });
    }

    const new_entry = store.AppEntry.init("yeet", "yote");
    try in.append(allocator, new_entry);

    for (in.list.items) |entry| {
        std.debug.print("out - name: {s}, key: {s}\n", .{ entry.name, entry.key });
    }

    try in.encryptToFile(
        allocator,
        io,
        "out",
        password,
    );
}
