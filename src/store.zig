const std = @import("std");

// look into std.crypto.nacl.SecretBox

pub const AppEntry = struct {
    name: []const u8,
    key: []const u8,

    pub fn init(name: []const u8, key: []const u8) AppEntry {
        return .{
            .name = name,
            .key = key,
        };
    }
};

pub const AppEntryList = struct {
    const Self = @This();

    list: std.ArrayList(AppEntry),

    pub fn init() Self {
        return .{
            .list = .empty,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.list.deinit(allocator);
    }

    pub fn append(self: *Self, allocator: std.mem.Allocator, app_entry: AppEntry) !void {
        for (self.list.items) |entry| {
            if (std.mem.eql(u8, app_entry.name, entry.name)) {
                return error.AppEntryNameExists;
            }
        }

        try self.list.append(allocator, app_entry);
    }

    pub fn parseJsonArray(
        self: *Self,
        allocator: std.mem.Allocator,
        json: []const u8,
    ) !void {
        const parsed = try std.json.parseFromSlice(
            []AppEntry,
            allocator,
            json,
            .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            },
        );
        defer parsed.deinit();

        try self.list.ensureUnusedCapacity(allocator, parsed.value.len);

        for (parsed.value) |entry| {
            self.list.appendAssumeCapacity(entry);
        }
    }

    pub fn encryptToFile(
        self: Self,
        allocator: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
        password: []const u8,
    ) !void {
        // encrypt AppEntryList to ciphertext
        _ = allocator;
        _ = password;
        const ciphertext = self.list.items;

        var file = try std.Io.Dir.cwd().createFile(io, path, .{
            .truncate = true,
        });
        defer file.close(io);

        var file_buf: [1024]u8 = undefined;
        var file_writer = file.writer(io, &file_buf);
        const file_out = &file_writer.interface;

        try file_out.print("{f}\n", .{std.json.fmt(
            ciphertext,
            .{ .whitespace = .indent_2 },
        )});
        try file_out.flush();
    }

    pub fn decryptFromFile(
        self: *Self,
        allocator: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
        key: []const u8,
    ) !void {
        _ = key;

        const content = try std.Io.Dir.readFileAlloc(
            std.Io.Dir.cwd(),
            io,
            path,
            allocator,
            .unlimited,
        );

        // decrypt here

        try self.parseJsonArray(allocator, content);
    }
};
