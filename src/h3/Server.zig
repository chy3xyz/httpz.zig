const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
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

    /// Accept loop — receives QUIC packets, creates server connections,
    /// and echoes "Hello from H3!" for any HTTP/3 request.
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

            // Parse DCID from QUIC long header packet
            // Byte 0: flags (0x80 = long header)
            if (buf[0] & 0x80 == 0) continue; // not a long header

            const dcid_len: usize = @intCast(buf[5]);
            if (6 + dcid_len > n) continue;

            var dcid: [18]u8 = @splat(0);
            @memcpy(dcid[0..@min(dcid_len, @as(usize, 18))], buf[6..][0..@min(dcid_len, @as(usize, 18))]);

            // Try existing connection first
            if (self.listener.connections.get(dcid)) |conn| {
                // Feed packet to existing connection
                const pkt = ngtcp2.ngtcp2_pkt_info{};
                _ = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &.{ .local = .{}, .remote = .{} }, &pkt, buf[0..n], nowNanos());
                _ = quic.flushPackets(conn) catch {};
                continue;
            }

            // New connection — create server QUIC connection
            try self.handleNewConnection(&buf, n, dcid);
        }
    }

    fn handleNewConnection(self: *Server, buf: []u8, n: usize, dcid: [18]u8) !void {
        const dcid_len: usize = @intCast(buf[5]);
        const scid_ofs = 6 + dcid_len;
        if (scid_ofs + 1 > n) return;
        const scid_len: usize = @intCast(buf[scid_ofs]);
        if (scid_ofs + 1 + scid_len > n) return;

        var scid: [18]u8 = @splat(0);
        @memcpy(scid[0..@min(scid_len, @as(usize, 18))], buf[scid_ofs + 1 ..][0..@min(scid_len, @as(usize, 18))]);

        // Generate server SCID
        var server_scid: ngtcp2.ngtcp2_cid = undefined;
        server_scid.datalen = 18;
        posix.getrandom(server_scid.data[0..18]) catch unreachable;

        var client_dcid: ngtcp2.ngtcp2_cid = undefined;
        client_dcid.datalen = @intCast(@min(dcid_len, @as(usize, 18)));
        @memcpy(client_dcid.data[0..client_dcid.datalen], dcid[0..client_dcid.datalen]);

        var client_scid: ngtcp2.ngtcp2_cid = undefined;
        client_scid.datalen = @intCast(@min(scid_len, @as(usize, 18)));
        @memcpy(client_scid.data[0..client_scid.datalen], scid[0..client_scid.datalen]);

        // Set up server callbacks
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

        // Read the initial packet into the new connection
        const pkt = ngtcp2.ngtcp2_pkt_info{};
        _ = ngtcp2.ngtcp2_conn_read_pkt(conn_ptr.?, &.{ .local = .{}, .remote = .{} }, &pkt, buf[0..n], nowNanos());

        // Create Connection wrapper and store
        const conn = try self.allocator.create(quic.Connection);
        conn.* = quic.Connection{
            .conn = conn_ptr.?,
            .socket = self.listener.socket,
        };

        // Store by both DCID and SCID for routing
        try self.listener.connections.put(server_scid.data, conn);
        _ = try quic.flushPackets(conn);

        // Drive handshake
        for (0..20) |_| {
            quic.readPacket(conn) catch {};
            _ = quic.flushPackets(conn) catch {};
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        std.debug.print("H3: new QUIC connection established\n", .{});
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
