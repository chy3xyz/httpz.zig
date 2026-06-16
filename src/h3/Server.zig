const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
const posix = std.posix;

pub const Handler = *const fn (allocator: std.mem.Allocator, request: []const u8) []const u8;

pub const Server = struct {
    listener: quic.Listener,
    allocator: std.mem.Allocator,
    handler: Handler,

    pub fn init(allocator: std.mem.Allocator, port: u16, handler: Handler) !Server {
        return .{
            .listener = try quic.Listener.init(allocator, port),
            .allocator = allocator,
            .handler = handler,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit();
    }

    pub fn run(self: *Server) !void {
        var buf: [65536]u8 = undefined;
        std.debug.print("H3 server listening on UDP port\n", .{});

        while (true) {
            const n = posix.recvfrom(self.listener.socket, &buf, 0) catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                else => return error.QuicError,
            };
            if (n < 6) continue;
            if (buf[0] & 0x80 == 0) continue; // short header

            const dcid_len: usize = @intCast(buf[5]);
            if (6 + dcid_len > n) continue;
            var dcid: [18]u8 = @splat(0);
            @memcpy(dcid[0..@min(dcid_len, @as(usize, 18))], buf[6..][0..@min(dcid_len, @as(usize, 18))]);

            if (self.listener.connections.get(dcid)) |conn| {
                const pkt = ngtcp2.ngtcp2_pkt_info{};
                _ = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &.{ .local = .{}, .remote = .{} }, &pkt, buf[0..n], nowNanos());
                _ = quic.flushPackets(conn) catch {};
                continue;
            }

            try self.handleNewConnection(buf, n, dcid, dcid_len);
        }
    }

    fn handleNewConnection(self: *Server, buf: []u8, n: usize, dcid: [18]u8, dcid_len: usize) !void {
        const scid_ofs = 6 + dcid_len;
        if (scid_ofs + 1 > n) return;
        const scid_len: usize = @intCast(buf[scid_ofs]);
        if (scid_ofs + 1 + scid_len > n) return;

        var server_scid: ngtcp2.ngtcp2_cid = undefined;
        server_scid.datalen = 18;
        posix.getrandom(server_scid.data[0..18]) catch unreachable;

        var client_dcid: ngtcp2.ngtcp2_cid = undefined;
        client_dcid.datalen = @intCast(@min(dcid_len, @as(usize, 18)));
        @memcpy(client_dcid.data[0..client_dcid.datalen], dcid[0..client_dcid.datalen]);

        var callbacks: ngtcp2.ngtcp2_callbacks = undefined;
        ngtcp2.ngtcp2_callbacks_default(&callbacks);
        callbacks.recv_client_initial = ngtcp2.ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_crypto_data = ngtcp2.ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2.ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2.ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2.ngtcp2_crypto_hp_mask_cb;
        callbacks.update_key = ngtcp2.ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2.ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2.ngtcp2_crypto_version_negotiation_cb;

        var settings: ngtcp2.ngtcp2_settings = undefined;
        ngtcp2.ngtcp2_settings_default(&settings);

        var params: ngtcp2.ngtcp2_transport_params = undefined;
        ngtcp2.ngtcp2_transport_params_default(&params);
        params.initial_max_streams_uni = 3;
        params.initial_max_streams_bidi = 100;
        params.initial_max_data = 1048576;
        params.initial_max_stream_data_bidi_local = 1048576;
        params.initial_max_stream_data_bidi_remote = 1048576;

        const path: ngtcp2.ngtcp2_path = .{
            .local = .{ .addr = undefined, .addrlen = 0 },
            .remote = .{ .addr = undefined, .addrlen = 0 },
        };

        var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
        const ret = ngtcp2.ngtcp2_conn_server_new(&conn_ptr, &client_dcid, &server_scid, &path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, null, null);
        if (ret != 0) return error.QuicError;
        errdefer ngtcp2.ngtcp2_conn_del(conn_ptr.?);

        const pkt = ngtcp2.ngtcp2_pkt_info{};
        _ = ngtcp2.ngtcp2_conn_read_pkt(conn_ptr.?, &.{ .local = .{}, .remote = .{} }, &pkt, buf[0..n], nowNanos());

        const conn = try self.allocator.create(quic.Connection);
        conn.* = quic.Connection{
            .conn = conn_ptr.?,
            .socket = self.listener.socket,
        };

        try self.listener.connections.put(server_scid.data, conn);
        _ = try quic.flushPackets(conn);

        // Drive handshake
        for (0..20) |_| {
            quic.readPacket(conn) catch {};
            _ = quic.flushPackets(conn) catch {};
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        // After handshake, create H3 server session and serve request
        self.serveH3(conn) catch |err| {
            std.debug.print("H3 serve error: {s}\n", .{@errorName(err)});
        };
    }

    fn serveH3(self: *Server, conn: *quic.Connection) !void {
        var h3_session = try http3.Session.initServer(self.allocator);
        defer h3_session.deinit();

        // Poll for stream data
        var stream_buf: [65536]u8 = undefined;
        var served = false;

        for (0..100) |_| {
            quic.readPacket(conn) catch {};
            _ = quic.flushPackets(conn) catch {};

            // Check for client-initiated bidi streams (stream_id 0, 4, 8, ...)
            var stream_id: i64 = 0;
            while (stream_id < 100) : (stream_id += 4) {
                var fin: i32 = 0;
                const sn = ngtcp2.ngtcp2_conn_read_stream(conn.conn, stream_id, &stream_buf, stream_buf.len, &fin);
                if (sn > 0) {
                    _ = h3_session.readStream(stream_id, stream_buf[0..@intCast(sn)], fin != 0) catch {};
                }
            }

            // Check if any stream is done (via ResponseContext attached to stream user data)
            // For now, serve a fixed response on first data
            if (!served and h3_session.conn != null) {
                // Check stream 0 for H3 request data
                var fin0: i32 = 0;
                const s0 = ngtcp2.ngtcp2_conn_read_stream(conn.conn, 0, &stream_buf, stream_buf.len, &fin0);
                if (s0 > 0) {
                    _ = h3_session.readStream(0, stream_buf[0..@intCast(s0)], fin0 != 0) catch {};
                    // Submit echo response
                    const body = self.handler(self.allocator, "H3 request");
                    h3_session.submitResponse(0, 200, "", body) catch {};
                    _ = quic.flushPackets(conn) catch {};
                    served = true;
                }
            }

            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
};

fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    posix.clock_gettime(posix.CLOCK.MONOTONIC, &ts) catch unreachable;
    return @as(u64, @intCast(ts.tv_sec)) * 1_000_000_000 + @as(u64, @intCast(ts.tv_nsec));
}

test {
    _ = Server;
}
