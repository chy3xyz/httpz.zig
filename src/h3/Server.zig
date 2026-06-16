const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
const posix = std.posix;

/// Sleep for a given number of nanoseconds.
fn sleepNs(ns: u64) void {
    const req = posix.timespec{
        .sec = @intCast(ns / 1_000_000_000),
        .nsec = @intCast(ns % 1_000_000_000),
    };
    _ = std.c.nanosleep(@ptrCast(&req), null);
}

/// Handler signature matching httpz convention: returns response body as bytes.
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
        std.debug.print("H3 server listening on UDP\n", .{});

        while (true) {
            const n = std.c.recvfrom(self.listener.socket, &buf, buf.len, 0, null, null);
            if (n < 0) {
                sleepNs(10 * std.time.ns_per_ms);
                continue;
            }
            if (n < 6) continue;
            if (buf[0] & 0x80 == 0) continue;

            const dcid_len: usize = @intCast(buf[5]);
            if (6 + dcid_len > @as(usize, @intCast(n))) continue;
            var dcid: [18]u8 = @splat(0);
            @memcpy(dcid[0..@min(dcid_len, @as(usize, 18))], buf[6..][0..@min(dcid_len, @as(usize, 18))]);

            if (self.listener.connections.get(dcid)) |conn| {
                const data = buf[0..@intCast(n)];
                const pkt = ngtcp2.ngtcp2_pkt_info{};
                var path: ngtcp2.ngtcp2_path = .{ .local = .{ .addr = undefined, .addrlen = 0 }, .remote = .{ .addr = undefined, .addrlen = 0 } };
                _ = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &path, &pkt, data.ptr, data.len, nowNanos());
                _ = quic.flushPackets(conn) catch {};
                continue;
            }

            try self.handleNewConnection(&buf, @intCast(n), dcid, dcid_len);
        }
    }

    fn handleNewConnection(self: *Server, buf: []u8, n: usize, dcid: [18]u8, dcid_len: usize) !void {
        const scid_ofs = 6 + dcid_len;
        if (scid_ofs + 1 > n) return;

        var server_scid: ngtcp2.ngtcp2_cid = undefined;
        server_scid.datalen = 18;
        std.c.arc4random_buf(@ptrCast(&server_scid.data), 18);

        var client_dcid: ngtcp2.ngtcp2_cid = undefined;
        client_dcid.datalen = @intCast(@min(dcid_len, @as(usize, 18)));
        @memcpy(client_dcid.data[0..client_dcid.datalen], dcid[0..client_dcid.datalen]);

        var callbacks: ngtcp2.ngtcp2_callbacks = std.mem.zeroes(ngtcp2.ngtcp2_callbacks);
        callbacks.recv_client_initial = quic.serverRecvClientInitialCb;
        callbacks.recv_crypto_data = ngtcp2.ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2.ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2.ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2.ngtcp2_crypto_hp_mask_cb;
        callbacks.update_key = ngtcp2.ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2.ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2.ngtcp2_crypto_version_negotiation_cb;
        callbacks.get_new_connection_id = quic.getNewConnIdCb;
        callbacks.remove_connection_id = quic.removeConnIdCb;
        callbacks.path_validation = quic.pathValidationCb;

        var settings: ngtcp2.ngtcp2_settings = undefined;
        ngtcp2.ngtcp2_settings_default(&settings);
        if (quic.qlog_fd >= 0) {
            settings.qlog_write = quic.qlogWriteCb;
        }

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
        const init_data = buf[0..n];
        var init_path: ngtcp2.ngtcp2_path = .{ .local = .{ .addr = undefined, .addrlen = 0 }, .remote = .{ .addr = undefined, .addrlen = 0 } };
        _ = ngtcp2.ngtcp2_conn_read_pkt(conn_ptr.?, &init_path, &pkt, init_data.ptr, init_data.len, nowNanos());

        const conn = try self.allocator.create(quic.Connection);
        conn.* = quic.Connection{
            .conn = conn_ptr.?,
            .socket = self.listener.socket,
        };

        var cid_key: [18]u8 = undefined;
        @memcpy(&cid_key, server_scid.data[0..18]);
        try self.listener.connections.put(cid_key, conn);
        _ = try quic.flushPackets(conn);

        // Drive handshake
        for (0..20) |_| {
            quic.readPacket(conn) catch {};
            _ = quic.flushPackets(conn) catch {};
            sleepNs(10 * std.time.ns_per_ms);
        }

        // After handshake, start H3 session
        self.serveH3(conn) catch |err| {
            std.debug.print("H3 serve error: {s}\n", .{@errorName(err)});
        };
    }

    /// H3 stream type constants (RFC 9114 §6.2)
    const H3_STREAM_CONTROL: u8 = 0x00;
    const H3_STREAM_QPACK_ENCODER: u8 = 0x02;
    const H3_STREAM_QPACK_DECODER: u8 = 0x03;

    fn serveH3(self: *Server, conn: *quic.Connection) !void {
        var h3 = try http3.Session.initServer(self.allocator);
        defer h3.deinit();

        var stream_buf: [65536]u8 = undefined;
        var control_bound = false;
        var qpack_enc_id: i64 = -1;
        var qpack_dec_id: i64 = -1;
        var requests_served: u32 = 0;

        // Poll loop: process incoming packets, bind streams, serve requests
        for (0..500) |_| {
            quic.readPacket(conn) catch {};
            _ = quic.flushPackets(conn) catch {};

            // Scan all possible QUIC streams for new data
            var stream_id: i64 = 0;
            while (stream_id < 64) : (stream_id += 1) {
                var fin: i32 = 0;
                const sn = ngtcp2.ngtcp2_conn_read_stream(conn.conn, stream_id, &stream_buf, stream_buf.len, &fin);

                if (sn <= 0) continue;
                const data = stream_buf[0..@intCast(sn)];

                if (isUniStream(stream_id)) {
                    if (data.len == 0) continue;
                    const stype = data[0];
                    const rest = if (data.len > 1) data[1..] else data[0..0];

                    switch (stype) {
                        H3_STREAM_CONTROL => {
                            if (!control_bound) {
                                _ = nghttp3.nghttp3_conn_bind_control_stream(h3.conn, stream_id);
                                control_bound = true;
                            }
                            if (rest.len > 0) {
                                _ = h3.readStream(stream_id, rest, fin != 0) catch {};
                            }
                        },
                        H3_STREAM_QPACK_ENCODER => {
                            qpack_enc_id = stream_id;
                            tryBindQpack(&h3, &control_bound, qpack_enc_id, qpack_dec_id);
                            if (rest.len > 0) {
                                _ = h3.readStream(stream_id, rest, fin != 0) catch {};
                            }
                        },
                        H3_STREAM_QPACK_DECODER => {
                            qpack_dec_id = stream_id;
                            tryBindQpack(&h3, &control_bound, qpack_enc_id, qpack_dec_id);
                            if (rest.len > 0) {
                                _ = h3.readStream(stream_id, rest, fin != 0) catch {};
                            }
                        },
                        else => {},
                    }
                } else if (isBidiClientStream(stream_id)) {
                    _ = h3.readStream(stream_id, data, fin != 0) catch {};

                    if (fin != 0 and requests_served < 10) {
                        const body = self.handler(self.allocator, "H3-request");
                        h3.submitResponse(stream_id, 200, "", body) catch {};
                        requests_served += 1;
                    }
                }
            }

            sleepNs(5 * std.time.ns_per_ms);
        }
    }

    fn tryBindQpack(h3: *http3.Session, control_bound: *bool, enc_id: i64, dec_id: i64) void {
        if (control_bound.* and enc_id >= 0 and dec_id >= 0) {
            h3.bindQpackStreams(enc_id, dec_id) catch {};
        }
    }

    fn isUniStream(stream_id: i64) bool {
        return (@as(u64, @intCast(stream_id)) & 0x02) != 0;
    }

    fn isBidiClientStream(stream_id: i64) bool {
        return (@as(u64, @intCast(stream_id)) & 0x03) == 0;
    }
};

fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    _ = std.c.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "H3 Server init/deinit" {
    var server = try Server.init(std.testing.allocator, 14433, echoHandler);
    defer server.deinit();
}

test "H3: TLS cert loading" {
    const cert_pem = @embedFile("test_cert.pem");
    const key_pem = @embedFile("test_key.pem");
    try quic.setServerCert(cert_pem, key_pem);
}

fn echoHandler(allocator: std.mem.Allocator, _: []const u8) []const u8 {
    return allocator.dupe(u8, "OK") catch "OK";
}

test {
    _ = Server;
}
