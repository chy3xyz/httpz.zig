const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");

pub const Client = struct {
    quic_conn: quic.Connection,
    h3_session: http3.Session,
    allocator: std.mem.Allocator,
    host: []const u8,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Client {
        const h3 = try http3.Session.init(allocator);
        errdefer h3.deinit();

        // Set up stream data bridge: ngtcp2 recv_stream_data → nghttp3 readStream
        const stream_ctx = quic.StreamDataCtx{
            .h3_conn = @ptrCast(h3.conn),
            .recv_stream_data = onQuicStreamData,
        };
        var qc = try quic.connect(host, port, stream_ctx, null);
        errdefer qc.deinit();

        return .{
            .quic_conn = qc,
            .h3_session = h3,
            .allocator = allocator,
            .host = host,
        };
    }

    pub fn deinit(self: *Client) void {
        self.h3_session.deinit();
        self.quic_conn.deinit();
    }

    /// Send a GET request, return response body as bytes.
    /// Caller owns the returned slice (allocated with self.allocator).
    pub fn get(self: *Client, path: []const u8) ![]const u8 {
        // 1. Open a bidirectional QUIC stream (retry up to 100 times)
        var stream_id: i64 = -1;
        for (0..100) |_| {
            const ret = ngtcp2.ngtcp2_conn_open_bidi_stream(self.quic_conn.conn, &stream_id, null);
            if (ret == 0) break;
            // Retry: flush, read, sleep
            quic.flushPackets(&self.quic_conn) catch {};
            quic.readPacket(&self.quic_conn) catch {};
            std.time.sleep(10 * std.time.ns_per_ms);
        }
        if (stream_id < 0) return error.QuicError;

        // 2. Submit HTTP/3 request
        try self.h3_session.submitRequest(stream_id, path, self.host);

        // 3. Set up response context on the nghttp3 stream
        var ctx = http3.ResponseContext.init(self.allocator);
        defer ctx.deinit();
        _ = nghttp3.nghttp3_conn_set_stream_user_data(self.h3_session.conn, stream_id, @ptrCast(&ctx));

        // 4. I/O loop: pump writes, read responses until done
        const start = std.time.milliTimestamp();
        while (!ctx.done) {
            // Pump outgoing data: nghttp3 → ngtcp2 → UDP
            pumpWrites(self);

            // Flush QUIC packets to UDP
            quic.flushPackets(&self.quic_conn) catch {};

            // Read incoming UDP packets — feeds QUIC engine which triggers
            // recv_stream_data → nghttp3 readStream → ctx populated
            quic.readPacket(&self.quic_conn) catch {};

            // Timeout after 30 seconds
            if (std.time.milliTimestamp() - start > 30000) return error.Timeout;

            std.time.sleep(1 * std.time.ns_per_ms);
        }

        // 5. Return body (copy to heap since ctx is stack-local)
        const result = try self.allocator.dupe(u8, ctx.body.items);
        return result;
    }
};

/// Bridge: ngtcp2 recv_stream_data callback → nghttp3 conn_read_stream2.
/// Called by quic.zig's recvStreamDataCb whenever stream data arrives.
fn onQuicStreamData(h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) void {
    const conn: *nghttp3.nghttp3_conn = @alignCast(@ptrCast(h3_conn));
    _ = nghttp3.nghttp3_conn_read_stream2(conn, stream_id, data.ptr, data.len, @intFromBool(fin));
}

/// Pump pending HTTP/3 write data (headers, etc.) into the QUIC connection.
fn pumpWrites(self: *Client) void {
    while (true) {
        var write_stream_id: i64 = -1;
        var write_fin: nghttp3.c_int = 0;
        var vec: nghttp3.nghttp3_vec = undefined;
        const nvec = nghttp3.nghttp3_conn_writev_stream(self.h3_session.conn, &write_stream_id, &write_fin, &vec, 1);
        if (nvec < 0) break;
        if (write_stream_id == -1) break;
        if (nvec > 0) {
            var pi: ngtcp2.ngtcp2_pkt_info = undefined;
            var dest: ngtcp2.ngtcp2_path = .{ .local = .{}, .remote = .{} };
            const nwritten = ngtcp2.ngtcp2_conn_write_stream_versioned(
                self.quic_conn.conn,
                &dest,
                ngtcp2.NGTCP2_PKT_INFO_VERSION,
                &pi,
                &self.quic_conn.buf,
                self.quic_conn.buf.len,
                null,
                0,
                write_stream_id,
                vec.base,
                vec.len,
                nowNanos(),
            );
            _ = nghttp3.nghttp3_conn_add_write_offset(self.h3_session.conn, write_stream_id, if (nwritten > 0) @as(usize, @intCast(nwritten)) else 0);
        } else if (write_fin != 0) {
            // Zero-length fin — just acknowledge
            _ = nghttp3.nghttp3_conn_add_write_offset(self.h3_session.conn, write_stream_id, 0);
        }
    }
}

fn nowNanos() u64 {
    var ts: std.posix.timespec = undefined;
    std.posix.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) catch unreachable;
    return @as(u64, @intCast(ts.tv_sec)) * 1_000_000_000 + @as(u64, @intCast(ts.tv_nsec));
}

test {
    _ = Client;
    _ = quic;
    _ = http3;
}
