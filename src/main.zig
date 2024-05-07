// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Jan Hendrik Farr

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const net = std.net;
const fs = std.fs;

const c = @cImport({
    @cInclude("quiche.h");
});

const MAX_DATAGRAM_SIZE = 1350;
const LOCAL_CONN_ID_LEN = 16;

const event_type = enum {
    SERVER,
    UPSTREAM,
    TIMER,
};

const request_data = struct {
    buf_upstream: [4096]u8,
    buf_upstream_slice: []u8,
    buf_dns: [4096]u8,
    buf_dns_slice: []u8,
    from: net.Address,
    stream_id: u64,
};

var requests: [16]request_data = undefined;

const quic_upstream = struct {
    sock: posix.socket_t,
    remote: net.Address,
    local: net.Address,
    conf: ?*c.quiche_config,
    conn: ?*c.quiche_conn,
    urandom: fs.File,
};

fn quic_upstream_init(u: *quic_upstream) !void {
    u.sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    errdefer posix.close(u.sock);
    _ = try posix.fcntl(u.sock, posix.F.SETFL, posix.SOCK.NONBLOCK);

    u.remote = try net.Address.parseIp("8.8.8.8", 443);
    try posix.connect(u.sock, &u.remote.any, u.remote.getOsSockLen());

    var upstream_local_len: posix.socklen_t = @sizeOf(net.Address);
    try posix.getsockname(u.sock, @ptrCast(&u.local), &upstream_local_len);

    u.urandom = try fs.openFileAbsolute("/dev/urandom", .{});
    errdefer u.urandom.close();

    const config = c.quiche_config_new(c.QUICHE_PROTOCOL_VERSION) orelse return error.nullptr;
    errdefer c.quiche_config_free(config);

    _ = c.quiche_config_set_application_protos(
        config,
        c.QUICHE_H3_APPLICATION_PROTOCOL,
        c.QUICHE_H3_APPLICATION_PROTOCOL.len,
    );

    c.quiche_config_set_max_idle_timeout(config, 300000);
    c.quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    c.quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    c.quiche_config_set_initial_max_data(config, 10000000);
    c.quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    c.quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    c.quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    c.quiche_config_set_initial_max_streams_bidi(config, 100);
    c.quiche_config_set_initial_max_streams_uni(config, 100);
    c.quiche_config_set_disable_active_migration(config, true);
    // c.quiche_config_enable_early_data(config);
    c.quiche_config_log_keys(config);

    u.conf = config;
}

fn quic_upstream_connect(u: *quic_upstream) !void {
    var cid: [LOCAL_CONN_ID_LEN]u8 = undefined;
    _ = try u.urandom.read(&cid);

    u.conn = c.quiche_connect(
        "dns.google",
        &cid,
        cid.len,
        @ptrCast(&u.local),
        u.local.getOsSockLen(),
        @ptrCast(&u.remote),
        u.remote.getOsSockLen(),
        u.conf,
    ) orelse return error.quiche_connect_error;
    _ = c.quiche_conn_set_keylog_path(u.conn, "/tmp/keys");
}

fn quic_upstream_free(u: *quic_upstream) void {
    if (u.conf != null) {
        c.quiche_config_free(u.conf);
    }
    if (u.conn != null) {
        c.quiche_conn_free(u.conn);
    }
    if (u.conf != null) {
        c.quiche_config_free(u.conf);
    }
    posix.close(u.sock);
    u.urandom.close();
}

const doh3_headers = [_]c.quiche_h3_header{
    .{
        .name = ":method",
        .name_len = ":method".len,
        .value = "POST",
        .value_len = "POST".len,
    },
    .{
        .name = ":scheme",
        .name_len = ":scheme".len,
        .value = "https",
        .value_len = "https".len,
    },
    .{
        .name = ":authority",
        .name_len = ":authority".len,
        .value = "dns.google",
        .value_len = "dns.google".len,
    },
    .{
        .name = ":path",
        .name_len = ":path".len,
        .value = "/dns-query",
        .value_len = "/dns-query".len,
    },
    .{
        .name = "user-agent",
        .name_len = "user-agent".len,
        .value = "quiche",
        .value_len = "quiche".len,
    },
    .{
        .name = "Accept",
        .name_len = "Accept".len,
        .value = "application/dns-message",
        .value_len = "application/dns-message".len,
    },
    .{
        .name = "Content-type",
        .name_len = "Content-type".len,
        .value = "application/dns-message",
        .value_len = "application/dns-message".len,
    },
};

pub fn flush_egress(u: *quic_upstream) void {
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    var send_info: c.quiche_send_info = undefined;

    const n_write = c.quiche_conn_send(u.conn, &out, out.len, &send_info);
    if (n_write > 0) {
        _ = posix.send(u.sock, out[0..@intCast(n_write)], 0) catch unreachable;
    }
}

pub fn main() !void {
    const server_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    _ = try posix.fcntl(server_fd, posix.F.SETFL, posix.SOCK.NONBLOCK);
    const server_addr = try net.Address.parseIp("127.0.0.1", 5503);
    try posix.bind(server_fd, &server_addr.any, server_addr.getOsSockLen());
    defer posix.close(server_fd);

    var q_upstream: quic_upstream = std.mem.zeroes(quic_upstream);
    try quic_upstream_init(&q_upstream);
    defer quic_upstream_free(&q_upstream);

    const epoll_fd: i32 = @bitCast(@as(u32, (@truncate(linux.epoll_create1(0)))));
    defer posix.close(epoll_fd);
    if (epoll_fd < 0) {
        return error.anyerror;
    }

    var server_event: linux.epoll_event = .{
        .events = linux.EPOLL.IN,
        .data = linux.epoll_data{ .u32 = @intFromEnum(event_type.SERVER) },
    };
    if (@as(i32, @bitCast(@as(u32, @truncate(linux.epoll_ctl(
        epoll_fd,
        linux.EPOLL.CTL_ADD,
        server_fd,
        &server_event,
    ))))) < 0) {
        return error.anyerror;
    }

    var upstream_event: linux.epoll_event = .{
        .events = linux.EPOLL.IN,
        .data = linux.epoll_data{ .u32 = @intFromEnum(event_type.UPSTREAM) },
    };
    if (@as(i32, @bitCast(@as(u32, @truncate(linux.epoll_ctl(
        epoll_fd,
        linux.EPOLL.CTL_ADD,
        q_upstream.sock,
        &upstream_event,
    ))))) < 0) {
        return error.anyerror;
    }

    const timer_fd = try posix.timerfd_create(linux.CLOCK.MONOTONIC, linux.TFD{ ._0 = 0 });

    var tspec: linux.itimerspec = .{
        .it_value = .{ .tv_sec = 0, .tv_nsec = 0 },
        .it_interval = .{ .tv_sec = 0, .tv_nsec = 0 },
    };
    try posix.timerfd_settime(timer_fd, @bitCast(@as(u32, 0)), &tspec, null);

    var timer_event: linux.epoll_event = .{
        .events = linux.EPOLL.IN,
        .data = linux.epoll_data{ .u32 = @intFromEnum(event_type.TIMER) },
    };

    if (@as(i32, @bitCast(@as(u32, @truncate(linux.epoll_ctl(
        epoll_fd,
        linux.EPOLL.CTL_ADD,
        timer_fd,
        &timer_event,
    ))))) < 0) {
        return error.anyerror;
    }

    var event_queue: [16]linux.epoll_event = undefined;

    const h3_conf = c.quiche_h3_config_new() orelse return error.quiche_h3_create_failed;
    defer c.quiche_h3_config_free(h3_conf);
    var h3_conn: ?*c.quiche_h3_conn = null;
    var request_id_received: u64 = 0;
    var request_id_sent: u64 = 0;
    var restart: bool = false;
    // var startup_unsent_requests: u64 = 0;
    defer c.quiche_h3_conn_free(h3_conn);

    // try quic_upstream_connect(&q_upstream);
    // flush_egress(&q_upstream);

    while (true) {
        const n_events: i32 = @bitCast(@as(u32, @truncate(linux.epoll_wait(
            epoll_fd,
            &event_queue,
            event_queue.len,
            -1,
        ))));
        if (n_events < 0) {
            continue;
        }

        for (event_queue[0..@as(u32, @bitCast(n_events))]) |event| {
            const t: event_type = @enumFromInt(event.data.u32);

            switch (t) {
                event_type.SERVER => {
                    // TODO: would have to be called right away if in-flight requests have to be retried
                    if (q_upstream.conn != null) {
                        if (c.quiche_conn_is_closed(q_upstream.conn) or restart) {
                            restart = false;
                            std.debug.print("connection is closed!\n", .{});
                            c.quiche_conn_free(q_upstream.conn);
                            q_upstream.conn = null;

                            if (h3_conn != null) {
                                c.quiche_h3_conn_free(h3_conn);
                                h3_conn = null;
                            }
                            request_id_received = 0;
                            request_id_sent = 0;
                        }
                    }

                    var request: *request_data = &requests[request_id_received % requests.len];
                    request.stream_id = request_id_received * 4;
                    request_id_received = request_id_received + 1;
                    // var out: [4096]u8 = undefined;
                    var from: net.Address = undefined;
                    var from_len: posix.socklen_t = @sizeOf(net.Address);
                    const n_read = try posix.recvfrom(server_fd, &request.buf_dns, 0, @ptrCast(&from), &from_len);
                    request.buf_dns_slice = request.buf_dns[0..n_read];
                    request.from = from;

                    if (q_upstream.conn == null) {
                        try quic_upstream_connect(&q_upstream);
                    }
                    // if (h3_conn != null) {
                    //     const stream_id = c.quiche_h3_send_request(h3_conn, q_upstream.conn, &doh3_headers, doh3_headers.len, false);
                    //     request = &requests[(@as(usize, @intCast(stream_id)) >> 2) % requests.len];
                    // } else {
                    //     startup_unsent_requests = startup_unsent_requests + 1;
                    //     request = &requests[(startup_unsent_requests % requests.len)];
                    // }
                    // // request.from = from;
                    // // request.buf_dns_slice = request.buf_dns[0..n_read];
                    // // @memcpy(request.buf_dns_slice, out[0..n_read]);
                    // _ = c.quiche_h3_send_body(h3_conn, q_upstream.conn, @bitCast(stream_id), &out, n_read, true);
                },
                event_type.UPSTREAM => {
                    var in: [4096]u8 = undefined;
                    const n_read = try posix.recv(q_upstream.sock, &in, 0);

                    var recv_info: c.quiche_recv_info = .{
                        .from = @ptrCast(&q_upstream.remote),
                        .from_len = q_upstream.remote.getOsSockLen(),
                        .to = @ptrCast(&q_upstream.local),
                        .to_len = q_upstream.local.getOsSockLen(),
                    };

                    if (n_read > 0) {
                        _ = c.quiche_conn_recv(q_upstream.conn, &in, n_read, &recv_info);
                    }

                    if (h3_conn != null) {
                        while (true) {
                            var h3_event: ?*c.quiche_h3_event = null;
                            const s = c.quiche_h3_conn_poll(h3_conn, q_upstream.conn, &h3_event);
                            if (s < 0) {
                                break;
                            }
                            defer c.quiche_h3_event_free(h3_event);

                            var request = &requests[(@as(usize, @intCast(s)) >> 2) % requests.len];

                            switch (c.quiche_h3_event_type(h3_event)) {
                                c.QUICHE_H3_EVENT_HEADERS => {},
                                c.QUICHE_H3_EVENT_DATA => {
                                    if (@rem(s, 4) == 0) {
                                        // TODO: call recv_body in loop and handle multiple data events on same stream
                                        const n_read_h3 = c.quiche_h3_recv_body(
                                            h3_conn,
                                            q_upstream.conn,
                                            @bitCast(s),
                                            &request.buf_upstream,
                                            request.buf_upstream.len,
                                        );
                                        request.buf_upstream_slice = request.buf_upstream[0..@bitCast(n_read_h3)];
                                    }
                                },
                                c.QUICHE_H3_EVENT_FINISHED => {
                                    if (@rem(s, 4) == 0) {
                                        _ = try posix.sendto(
                                            server_fd,
                                            request.buf_upstream_slice,
                                            0,
                                            @ptrCast(&request.from),
                                            request.from.getOsSockLen(),
                                        );
                                    }
                                },
                                c.QUICHE_H3_EVENT_GOAWAY => {
                                    std.debug.print("GOAWAY received. s: {}\n", .{s});
                                    restart = true;
                                },
                                c.QUICHE_H3_EVENT_RESET => {},
                                c.QUICHE_H3_EVENT_PRIORITY_UPDATE => {},
                                else => unreachable,
                            }
                        }
                    }
                },
                event_type.TIMER => {
                    c.quiche_conn_on_timeout(q_upstream.conn);
                },
            }
            if (c.quiche_conn_is_established(q_upstream.conn) and h3_conn == null) {
                h3_conn = c.quiche_h3_conn_new_with_transport(q_upstream.conn, h3_conf) orelse return error.h3_conn_create_failed;
            }

            if (h3_conn != null) {
                for (request_id_sent..request_id_received) |i| {
                    std.debug.print("request id: {}\n", .{i});
                    const request: *request_data = &requests[i % requests.len];
                    const stream_id = c.quiche_h3_send_request(h3_conn, q_upstream.conn, &doh3_headers, doh3_headers.len, false);
                    _ = c.quiche_h3_send_body(h3_conn, q_upstream.conn, @bitCast(stream_id), request.buf_dns_slice.ptr, request.buf_dns_slice.len, true);
                }
                request_id_sent = request_id_received;
            }

            flush_egress(&q_upstream);

            const ns = c.quiche_conn_timeout_as_nanos(q_upstream.conn);
            tspec = .{
                .it_value = .{
                    .tv_sec = @as(isize, @intCast(@divTrunc(ns, 1_000_000_000))),
                    .tv_nsec = @as(isize, @intCast(@rem(ns, 1_000_000_000))),
                },
                .it_interval = .{ .tv_sec = 0, .tv_nsec = 0 },
            };
            try posix.timerfd_settime(timer_fd, @bitCast(@as(u32, 0)), &tspec, null);
        }
    }
}
