const std = @import("std");
const quic = @import("quic.zig");
const posix = std.posix;

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

    /// Accept loop — for MVP, just log received packets.
    /// Full handler integration pending HTTP/3 request parsing.
    pub fn run(self: *Server) !void {
        var buf: [65536]u8 = undefined;
        std.debug.print("H3 server listening on UDP :{d}\n", .{self.listener.socket});

        while (true) {
            const n = posix.recvfrom(self.listener.socket, &buf, 0) catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                else => return error.QuicError,
            };
            std.debug.print("H3: received {d} bytes\n", .{n});
        }
    }
};

test {
    _ = Server;
}
