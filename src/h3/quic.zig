const std = @import("std");
const ngtcp2 = @import("ngtcp2_c");
const posix = std.posix;

pub const Connection = struct {
    conn: *ngtcp2.ngtcp2_conn,
    socket: posix.fd_t,
    allocator: std.mem.Allocator,
    buf: [65536]u8 = undefined,

    pub fn deinit(self: *Connection) void {
        ngtcp2.ngtcp2_conn_del(self.conn);
    }
};

pub const Error = error{
    QuicError,
    HandshakeFailed,
    ConnectionClosed,
    OutOfMemory,
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
            if (n == @intCast(@intFromEnum(ngtcp2.NGTCP2_ERR_WOULDBLOCK))) return;
            return error.QuicError;
        }
        _ = posix.sendto(conn.socket, conn.buf[0..@intCast(n)], 0, posix.sockaddr{}, 0) catch return error.QuicError;
    }
}
