const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;

extern "kernel32" fn GetStdHandle(
    nStdHandle: STD_HANDLE,
) callconv(.winapi) win.HANDLE;

const STD_HANDLE = enum(win.DWORD) {
    INPUT_HANDLE = 4294967286,
    OUTPUT_HANDLE = 4294967285,
    ERROR_HANDLE = 4294967284,
};

extern "kernel32" fn GetConsoleMode(
    hConsoleHandle: ?win.HANDLE,
    lpMode: ?*win.DWORD,
) callconv(.winapi) win.BOOL;

const ENABLE_ECHO_INPUT: win.DWORD = 0x0004;
// I don't care enough to add the others right now..

extern "kernel32" fn SetConsoleMode(
    hConsoleHandle: ?win.HANDLE,
    dwMode: win.DWORD,
) callconv(.winapi) win.BOOL;

pub fn setTerminalEcho(on: bool) !void {
    if (!(builtin.os.tag == .windows)) {
        return error.NotWindows; // I'm just on windows for now
    }

    const stdin_handle = GetStdHandle(.INPUT_HANDLE);

    var mode: win.DWORD = undefined;
    const get_console_res = GetConsoleMode(stdin_handle, &mode);
    if (!get_console_res.toBool()) {
        return error.GetConsoleModeFailed;
    }

    const set_mode = if (on) mode | ENABLE_ECHO_INPUT else mode & ~ENABLE_ECHO_INPUT;
    const set_console_res = SetConsoleMode(stdin_handle, set_mode);
    if (!set_console_res.toBool()) {
        return error.SetConsoleModeFailed;
    }
}

pub fn promptSecret(prompt: []const u8, stdin: *std.Io.Reader, stdout: *std.Io.Writer) ![]const u8 {
    try stdout.print("{s}\n", .{prompt});
    try stdout.flush();

    try setTerminalEcho(false);
    defer setTerminalEcho(true) catch {};

    const input = try stdin.takeDelimiterExclusive('\n');
    const secret = std.mem.trimEnd(u8, input, "\r");

    try stdout.print("\n", .{});
    try stdout.flush();

    return secret;
}
