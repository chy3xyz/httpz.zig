const std = @import("std");
const ngtcp2 = @import("ngtcp2_c");
const posix = std.posix;

const max_datagram_size = 65536;

pub const Error = error{QuicError};

pub const Connection = struct {
    conn: *ngtcp2.ngtcp2_conn,
    socket: posix.fd_t,
    buf: [max_datagram_size]u8 = undefined,

    pub fn deinit(self: *Connection) void {
        ngtcp2.ngtcp2_conn_del(self.conn);
        posix.close(self.socket);
        self.* = undefined;
    }
};

/// Get nanoseconds until next QUIC timer fires, or null if idle.
pub fn getExpiry(conn: *Connection) ?u64 {
    const ts = ngtcp2.ngtcp2_conn_get_expiry(conn.conn);
    if (ts == std.math.maxInt(u64)) return null;
    return ts;
}

/// Handle QUIC timer expiry — call when getExpiry time elapses.
pub fn handleExpiry(conn: *Connection) Error!void {
    const ret = ngtcp2.ngtcp2_conn_handle_expiry(conn.conn, nowNanos());
    if (ret != 0) return error.QuicError;
    _ = try flushPackets(conn);
}

fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    posix.clock_gettime(posix.CLOCK.MONOTONIC, &ts) catch unreachable;
    return @as(u64, @intCast(ts.tv_sec)) * 1_000_000_000 + @as(u64, @intCast(ts.tv_nsec));
}

/// Read a UDP packet and feed it to the QUIC connection.
pub fn readPacket(conn: *Connection) Error!void {
    const n = posix.recvfrom(conn.socket, &conn.buf, 0) catch |err| switch (err) {
        error.WouldBlock => return,
        else => return error.QuicError,
    };
    const pkt = ngtcp2.ngtcp2_pkt_info{};
    const ret = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &.{ .local = .{}, .remote = .{} }, &pkt, conn.buf[0..n], nowNanos());
    if (ret != 0) return error.QuicError;
}

/// Write any pending QUIC packets to the UDP socket.
pub fn flushPackets(conn: *Connection) Error!void {
    while (true) {
        var pi: ngtcp2.ngtcp2_pkt_info = undefined;
        var dest: ngtcp2.ngtcp2_path = .{ .local = .{}, .remote = .{} };
        const n = ngtcp2.ngtcp2_conn_write_pkt_versioned(conn.conn, &dest, &pi, &conn.buf, conn.buf.len, nowNanos(), ngtcp2.NGTCP2_WRITE_PKT_FLAG_NONE);
        if (n < 0) {
            if (n == @intFromEnum(ngtcp2.NGTCP2_ERR_WOULDBLOCK)) return;
            return error.QuicError;
        }
        _ = posix.sendto(conn.socket, conn.buf[0..@intCast(n)], 0, @ptrCast(@alignCast(dest.remote.addr orelse return error.QuicError)), @intCast(dest.remote.addrlen)) catch return error.QuicError;
    }
}

/// Create a QUIC client connection and perform handshake over UDP.
pub fn connect(host: []const u8, port: u16) Error!Connection {
    const addr = try posix.getAddressList(std.heap.page_allocator, host, port);
    defer addr.deinit();

    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(sock);

    const server_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = @byteSwap(port),
        .addr = addr.addrs[0].in.sa.addr,
        .zero = @splat(0),
    };

    // Generate random connection IDs
    var dcid: ngtcp2.ngtcp2_cid = undefined;
    var scid: ngtcp2.ngtcp2_cid = undefined;
    dcid.datalen = 18;
    scid.datalen = 18;
    posix.getrandom(dcid.data[0..18]) catch unreachable;
    posix.getrandom(scid.data[0..18]) catch unreachable;

    var callbacks: ngtcp2.ngtcp2_callbacks = undefined;
    ngtcp2.ngtcp2_callbacks_default(&callbacks);
    callbacks.client_initial = ngtcp2.ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2.ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2.ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2.ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2.ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2.ngtcp2_crypto_recv_retry_cb;
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
        .remote = .{
            .addr = @ptrCast(&server_addr),
            .addrlen = @sizeOf(posix.sockaddr.in),
        },
    };

    var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
    const ret = ngtcp2.ngtcp2_conn_client_new(&conn_ptr, &dcid, &scid, &path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, null, null);
    if (ret != 0) return error.QuicError;

    var self = Connection{
        .conn = conn_ptr.?,
        .socket = sock,
    };
    errdefer self.deinit();

    // Drive handshake
    _ = try flushPackets(&self);
    for (0..10) |_| {
        readPacket(&self) catch {};
        _ = flushPackets(&self) catch {};
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    return self;
}

/// Server-side QUIC listener, binds UDP and routes by Connection ID.
pub const Listener = struct {
    socket: posix.fd_t,
    connections: std.AutoHashMap([18]u8, *Connection),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, port: u16) Error!Listener {
        const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer posix.close(sock);

        const addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = @byteSwap(port),
            .addr = posix.inAddrAny,
            .zero = @splat(0),
        };
        try posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));

        return .{
            .socket = sock,
            .connections = std.AutoHashMap([18]u8, *Connection).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Listener) void {
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();
        posix.close(self.socket);
    }
};
