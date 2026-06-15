const std = @import("std");
const nghttp3 = @import("nghttp3_c");

pub const Session = struct {
    conn: *nghttp3.nghttp3_conn,
    callbacks: nghttp3.nghttp3_callbacks,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Session {
        var callbacks: nghttp3.nghttp3_callbacks = undefined;
        nghttp3.nghttp3_callbacks_default(&callbacks);

        var conn_ptr: ?*nghttp3.nghttp3_conn = null;
        const ret = nghttp3.nghttp3_conn_client_new(&conn_ptr, &callbacks, null, null);
        if (ret != 0) return error.H3Error;

        return .{
            .conn = conn_ptr.?,
            .callbacks = callbacks,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Session) void {
        nghttp3.nghttp3_conn_del(self.conn);
        self.* = undefined;
    }
};

pub const Error = error{
    H3Error,
};
