const std = @import("std");
const quic = @import("quic.zig");

pub const Server = struct {
    listener: quic.Listener,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, port: u16) !Server {
        return .{
            .listener = try quic.Listener.init(allocator, port),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit();
    }

    pub fn run(_: *Server) !void {
        return error.NotImplemented;
    }
};

test {
    _ = Server;
}
