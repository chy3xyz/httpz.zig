const std = @import("std");
const httpz = @import("httpz");
const h3 = httpz.h3;
const quic = h3.quic;

const builtin = @import("builtin");

test "H3: end-to-end client ↔ server" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    // Load test cert
    const cert_pem = @embedFile("cert.pem");
    const key_pem = @embedFile("key.pem");
    try quic.setServerCert(cert_pem, key_pem);

    const port: u16 = 14433;

    // Start server in background thread
    const ServerThread = struct {
        fn run() void {
            var server = h3.Server.init(std.heap.page_allocator, port, echoHandler) catch return;
            defer server.deinit();
            server.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{});
    defer thread.join();

    // Wait for server to bind
    std.Thread.yield() catch {};

    // Connect client
    var client = try h3.Client.init(std.testing.allocator, "127.0.0.1", port);
    defer client.deinit();

    // Send request
    const body = try client.get("/test");
    defer std.testing.allocator.free(body);

    // Verify
    try std.testing.expectEqualStrings("Hello from H3!", body);
}

fn echoHandler(allocator: std.mem.Allocator, _: []const u8) []const u8 {
    return allocator.dupe(u8, "Hello from H3!") catch "error";
}
