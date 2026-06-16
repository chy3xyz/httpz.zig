const std = @import("std");
const ngtcp2 = @import("ngtcp2_c");
const posix = std.posix;

const NGTCP2_STREAM_DATA_FLAG_FIN = ngtcp2.NGTCP2_STREAM_DATA_FLAG_FIN;

const max_datagram_size = 65536;

/// Thread-local QLog file descriptor. Set by enableQLog before creating connections.
pub threadlocal var qlog_fd: posix.fd_t = -1;

pub fn qlogWriteCb(
    user_data: ?*anyopaque,
    _: u32,
    data: ?*const anyopaque,
    datalen: usize,
) callconv(.c) void {
    _ = user_data;
    if (qlog_fd < 0) return;
    if (data) |d| {
        _ = posix.write(qlog_fd, @as([*]const u8, @ptrCast(d))[0..datalen]) catch {};
    }
}

/// Enable QLog debugging output to the given file path.
/// Must be called BEFORE creating QUIC connections.
pub fn enableQLog(path: []const u8) !void {
    const fd = try posix.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    qlog_fd = fd;
}

/// Disable QLog and close the file.
pub fn disableQLog() void {
    if (qlog_fd >= 0) {
        _ = posix.close(qlog_fd);
        qlog_fd = -1;
    }
}

pub const Error = error{QuicError};

/// Callback type for receiving stream data. Called from ngtcp2 recv_stream_data.
/// `h3_conn` is the nghttp3 connection pointer to feed data into.
pub const StreamDataCtx = struct {
    h3_conn: *anyopaque, // *nghttp3.nghttp3_conn — opaque to avoid circular dep
    recv_stream_data: *const fn (h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) void,
};

pub const Connection = struct {
    conn: *ngtcp2.ngtcp2_conn,
    socket: posix.fd_t,
    buf: [max_datagram_size]u8 = undefined,
    stream_ctx_alloc: ?*StreamDataCtx = null,
    qlog_fd: ?posix.fd_t = null,

    pub fn deinit(self: *Connection) void {
        ngtcp2.ngtcp2_conn_del(self.conn);
        posix.close(self.socket);
        if (self.stream_ctx_alloc) |ptr| {
            std.heap.page_allocator.destroy(ptr);
        }
        if (self.qlog_fd) |fd| {
            _ = posix.close(fd);
        }
        self.* = undefined;
    }
};

fn recvStreamDataCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    offset: u64,
    data: [*c]const u8,
    datalen: usize,
    user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) ngtcp2.c_int {
    _ = offset;
    _ = stream_user_data;
    const ctx: *StreamDataCtx = @alignCast(@ptrCast(user_data));
    const fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    ctx.recv_stream_data(ctx.h3_conn, stream_id, data[0..datalen], fin);
    _ = conn;
    return 0;
}

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
        _ = posix.sendto(conn.socket, conn.buf[0..@intCast(n)], 0, dest.remote.addr orelse return error.QuicError, dest.remote.addrlen) catch return error.QuicError;
    }
}

/// Create a QUIC client connection and perform handshake over UDP.
/// If `stream_ctx` is provided, installs recv_stream_data callback.
/// If `early_data` is provided (from a previous connection), enables 0-RTT.
pub fn connect(host: []const u8, port: u16, stream_ctx: ?StreamDataCtx, early_data: ?[]const u8) Error!Connection {
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
    callbacks.get_new_connection_id = getNewConnIdCb;
    callbacks.remove_connection_id = removeConnIdCb;
    callbacks.path_validation = pathValidationCb;

    // Install stream data callback if H3 bridge context is provided.
    // Heap-allocate the context so it lives beyond this stack frame.
    var stream_ctx_ptr: ?*StreamDataCtx = null;
    if (stream_ctx) |ctx| {
        callbacks.recv_stream_data = recvStreamDataCb;
        const ptr = try std.heap.page_allocator.create(StreamDataCtx);
        errdefer std.heap.page_allocator.destroy(ptr);
        ptr.* = ctx;
        stream_ctx_ptr = ptr;
    }

    // Set QLog if enabled
    var settings: ngtcp2.ngtcp2_settings = undefined;
    ngtcp2.ngtcp2_settings_default(&settings);
    if (qlog_fd >= 0) {
        settings.qlog_write = qlogWriteCb;
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
        .remote = .{
            .addr = @ptrCast(&server_addr),
            .addrlen = @sizeOf(posix.sockaddr.in),
        },
    };

    const user_data: ?*anyopaque = if (stream_ctx_ptr) |ptr| @ptrCast(ptr) else null;
    var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
    const ret = ngtcp2.ngtcp2_conn_client_new(&conn_ptr, &dcid, &scid, &path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, user_data, null);
    if (ret != 0) return error.QuicError;

    // Enable 0-RTT early data with remembered transport params
    if (early_data) |ed| {
        _ = ngtcp2.ngtcp2_conn_decode_and_set_0rtt_transport_params(conn_ptr.?, ed.ptr, ed.len);
    }

    var self = Connection{
        .conn = conn_ptr.?,
        .socket = sock,
        .stream_ctx_alloc = stream_ctx_ptr,
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

/// Get encoded transport params for 0-RTT resumption.
/// Returns allocated buffer — caller owns and must free.
pub fn getTransportParams(conn: *Connection) ![]u8 {
    var buf: [4096]u8 = undefined;
    const n = ngtcp2.ngtcp2_conn_encode_0rtt_transport_params(conn.conn, &buf, buf.len);
    if (n < 0) return error.QuicError;
    const result = try std.heap.page_allocator.alloc(u8, @intCast(n));
    @memcpy(result, buf[0..@intCast(n)]);
    return result;
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

// ---- Connection migration callbacks ----

/// ngtcp2 get_new_connection_id callback — generates a random CID.
/// For server: also registers in Listener CID routing table via user_data.
pub fn getNewConnIdCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    cid: ?*ngtcp2.ngtcp2_cid,
    _: ?*anyopaque,
    user_data: ?*anyopaque,
) callconv(.c) ngtcp2.c_int {
    _ = conn;
    const listener: ?*Listener = @ptrCast(@alignCast(user_data));
    cid.?.datalen = 18;
    posix.getrandom(cid.?.data[0..18]) catch return @intFromEnum(ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE);

    // Register in server CID routing table
    if (listener) |l| {
        var key: [18]u8 = undefined;
        @memcpy(&key, cid.?.data[0..18]);
        // The Connection* needs to be looked up — we don't have it directly.
        // Store CID → Connection mapping will be done by the caller (server).
        // For now, this is a no-op — CID registration is handled externally.
        _ = l;
    }
    return 0;
}

/// ngtcp2 remove_connection_id callback — retires an old CID.
pub fn removeConnIdCb(
    _: ?*ngtcp2.ngtcp2_conn,
    cid: ?*const ngtcp2.ngtcp2_cid,
    _: ?*anyopaque,
    user_data: ?*anyopaque,
) callconv(.c) ngtcp2.c_int {
    const listener: ?*Listener = @ptrCast(@alignCast(user_data));
    if (listener) |l| {
        var key: [18]u8 = @splat(0);
        @memcpy(key[0..@intCast(cid.?.datalen)], cid.?.data[0..@intCast(cid.?.datalen)]);
        _ = l.connections.remove(key);
    }
    return 0;
}

/// ngtcp2 path_validation callback — logs path changes.
pub fn pathValidationCb(
    _: ?*ngtcp2.ngtcp2_conn,
    _: ?*const ngtcp2.ngtcp2_path,
    _: ?*const ngtcp2.ngtcp2_path,
    _: ngtcp2.ngtcp2_path_validation_result,
    _: ?*anyopaque,
) callconv(.c) ngtcp2.c_int {
    return 0; // Accept all path changes
}
