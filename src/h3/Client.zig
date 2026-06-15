const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");

pub const Client = struct {
    quic_conn: quic.Connection,
    h3_session: http3.Session,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Client {
        var qc = try quic.connect(host, port);
        errdefer qc.deinit();

        const h3 = try http3.Session.init(allocator);

        return .{
            .quic_conn = qc,
            .h3_session = h3,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Client) void {
        self.h3_session.deinit();
        self.quic_conn.deinit();
    }

    /// Send a GET request, return response body as bytes.
    pub fn get(self: *Client, path: []const u8) ![]const u8 {
        _ = path;
        _ = self;
        return error.NotImplemented;
    }
};

test {
    _ = Client;
    _ = quic;
    _ = http3;
}
