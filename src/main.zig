// SPDX-License-Identifier: GPL-2.0-only                                                                          │
// Copyright (C) 2024 Jan Hendrik Farr

const std = @import("std");
const quiche = @cImport({
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
    buf: [4096]u8,
    buf_slice: []u8,
    from: std.net.Address,
};

var requests: [16]request_data = undefined;

const doh3_headers = [_]quiche.quiche_h3_header{
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

pub fn flush_egress(conn: ?*quiche.quiche_conn, upstream: std.posix.socket_t) void {
    var out: [MAX_DATAGRAM_SIZE]u8 = undefined;
    var send_info: quiche.quiche_send_info = undefined;

    const n_write = quiche.quiche_conn_send(conn, &out, out.len, &send_info);
    if (n_write > 0) {
        // std.debug.print("writing {} bytes to upstream\n", .{n_write});
        _ = std.posix.send(upstream, out[0..@intCast(n_write)], 0) catch unreachable;
    }
}

pub fn main() !void {
    const server_fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    _ = try std.posix.fcntl(server_fd, std.posix.F.SETFL, std.posix.SOCK.NONBLOCK);
    const server_addr = try std.net.Address.parseIp("127.0.0.1", 5503);
    try std.posix.bind(server_fd, &server_addr.any, server_addr.getOsSockLen());
    defer std.posix.close(server_fd);

    // var dns_request_stream_id: u64 = undefined;
    // var dns_request_buf: [4096]u8 = undefined;
    // var dns_request_buf_n_read: isize = undefined;
    // var dns_request_from: std.net.Address = undefined;

    const upstream_fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    _ = try std.posix.fcntl(server_fd, std.posix.F.SETFL, std.posix.SOCK.NONBLOCK);
    var upstream_addr = try std.net.Address.parseIp("8.8.8.8", 443);
    try std.posix.connect(upstream_fd, &upstream_addr.any, upstream_addr.getOsSockLen());
    defer std.posix.close(upstream_fd);

    // std.debug.print("server_fd: {}\n", .{server_fd});
    // std.debug.print("upstream fd: {}\n", .{upstream_fd});

    const config = quiche.quiche_config_new(quiche.QUICHE_PROTOCOL_VERSION) orelse return;

    _ = quiche.quiche_config_set_application_protos(
        config,
        quiche.QUICHE_H3_APPLICATION_PROTOCOL,
        quiche.QUICHE_H3_APPLICATION_PROTOCOL.len,
    );

    quiche.quiche_config_set_max_idle_timeout(config, 300000);
    quiche.quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche.quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche.quiche_config_set_initial_max_data(config, 10000000);
    quiche.quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche.quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche.quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche.quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche.quiche_config_set_initial_max_streams_uni(config, 100);
    quiche.quiche_config_set_disable_active_migration(config, true);
    // quiche.quiche_config_enable_early_data(config);
    quiche.quiche_config_log_keys(config);

    var cid: [LOCAL_CONN_ID_LEN]u8 = undefined;
    var urandom = try std.fs.openFileAbsolute("/dev/urandom", .{});
    defer urandom.close();
    _ = try urandom.read(&cid);
    // std.debug.print("read {} bytes from /dev/urandom\n", .{r});
    // std.debug.print("cid: {any}\n", .{cid});

    var upstream_local: std.net.Address = undefined;
    var upstream_local_len: std.posix.socklen_t = @sizeOf(std.net.Address);
    try std.posix.getsockname(upstream_fd, @ptrCast(&upstream_local), &upstream_local_len);
    const conn = quiche.quiche_connect(
        "dns.google",
        &cid,
        cid.len,
        @ptrCast(&upstream_local),
        upstream_local_len,
        @ptrCast(&upstream_addr),
        upstream_addr.getOsSockLen(),
        config,
    );

    if (conn == null) {
        return error.quiche_connect_error;
    }

    // std.debug.print("casting: {}\n", .{@as(i8, @truncate(@as(i32, -1)))});
    const epoll_fd: i32 = @truncate(@as(isize, (@bitCast(std.os.linux.epoll_create1(0)))));
    defer std.posix.close(epoll_fd);
    if (epoll_fd < 0) {
        return error.anyerror;
    }
    // const epoll_fd: i32 = @truncate(epoll_fd_64);
    // std.debug.print("epoll_fd: {}\n", .{epoll_fd});
    // std.debug.print("{}\n", .{config});

    var server_event: std.os.linux.epoll_event = .{
        .events = std.os.linux.EPOLL.IN,
        .data = std.os.linux.epoll_data{ .u32 = @intFromEnum(event_type.SERVER) },
    };
    if (std.os.linux.epoll_ctl(
        epoll_fd,
        std.os.linux.EPOLL.CTL_ADD,
        server_fd,
        &server_event,
    ) < 0) {
        return error.anyerror;
    }

    var upstream_event: std.os.linux.epoll_event = .{
        .events = std.os.linux.EPOLL.IN,
        .data = std.os.linux.epoll_data{ .u32 = @intFromEnum(event_type.UPSTREAM) },
    };
    if (std.os.linux.epoll_ctl(
        epoll_fd,
        std.os.linux.EPOLL.CTL_ADD,
        upstream_fd,
        &upstream_event,
    ) < 0) {
        return error.anyerror;
    }

    const timer_fd = try std.posix.timerfd_create(std.os.linux.CLOCK.MONOTONIC, std.os.linux.TFD{ ._0 = 0 });
    // std.debug.print("timer_fd: {}\n", .{timer_fd});

    var tspec: std.os.linux.itimerspec = .{
        .it_value = .{ .tv_sec = 0, .tv_nsec = 0 },
        .it_interval = .{ .tv_sec = 0, .tv_nsec = 0 },
    };
    try std.posix.timerfd_settime(timer_fd, @bitCast(@as(u32, 0)), &tspec, null);

    var timer_event: std.os.linux.epoll_event = .{
        .events = std.os.linux.EPOLL.IN,
        .data = std.os.linux.epoll_data{ .u32 = @intFromEnum(event_type.TIMER) },
    };

    if (std.os.linux.epoll_ctl(
        epoll_fd,
        std.os.linux.EPOLL.CTL_ADD,
        timer_fd,
        &timer_event,
    ) < 0) {
        return error.anyerror;
    }

    var event_queue: [16]std.os.linux.epoll_event = undefined;

    _ = quiche.quiche_conn_set_keylog_path(conn, "/tmp/keys");

    const h3_conf = quiche.quiche_h3_config_new() orelse return error.quiche_h3_create_failed;
    var h3_conn: ?*quiche.quiche_h3_conn = null;

    flush_egress(conn, upstream_fd);

    while (true) {
        const n_events = std.os.linux.epoll_wait(epoll_fd, &event_queue, event_queue.len, -1);

        for (event_queue[0..n_events]) |event| {
            const t: event_type = @enumFromInt(event.data.u32);
            switch (t) {
                event_type.SERVER => {
                    // std.debug.print("server event\n", .{});
                    var out: [4096]u8 = undefined;
                    var from: std.net.Address = undefined;
                    var from_len: std.posix.socklen_t = @sizeOf(std.net.Address);
                    const n_read = try std.posix.recvfrom(server_fd, &out, 0, @ptrCast(&from), &from_len);
                    // std.debug.print("{} : {any}\n", .{ from, out[0..n_read] });

                    // dns_request_from = from;

                    // quiche.quiche_conn_is

                    const stream_id = quiche.quiche_h3_send_request(h3_conn, conn, &doh3_headers, doh3_headers.len, false);
                    std.debug.print("stream id: {}\n", .{stream_id});
                    // dns_request_stream_id = @bitCast(stream_id);
                    var request = &requests[(@as(u64, @intCast(stream_id)) >> 2) % requests.len];
                    request.from = from;

                    _ = quiche.quiche_h3_send_body(h3_conn, conn, @bitCast(stream_id), &out, n_read, true);
                },
                event_type.UPSTREAM => {
                    // std.debug.print("upstream event\n", .{});
                    var in: [4096]u8 = undefined;
                    const n_read = try std.posix.recv(upstream_fd, &in, 0);
                    // std.debug.print("{} bytes from upstream\n", .{n_read});

                    var recv_info: quiche.quiche_recv_info = .{
                        .from = @ptrCast(&upstream_addr),
                        .from_len = upstream_addr.getOsSockLen(),
                        .to = @ptrCast(&upstream_local),
                        .to_len = upstream_local_len,
                    };

                    if (n_read > 0) {
                        _ = quiche.quiche_conn_recv(conn, &in, n_read, &recv_info);
                    }

                    if (h3_conn != null) {
                        while (true) {
                            var h3_event: ?*quiche.quiche_h3_event = null;
                            const s = quiche.quiche_h3_conn_poll(h3_conn, conn, &h3_event);
                            if (s < 0) {
                                break;
                            }
                            // std.debug.print("h3 event on stream {}\n", .{s});

                            // var request = &requests[(s >> 2) % requests.len];
                            var request = &requests[(@as(u64, @intCast(s)) >> 2) % requests.len];

                            switch (quiche.quiche_h3_event_type(h3_event)) {
                                quiche.QUICHE_H3_EVENT_HEADERS => {},
                                quiche.QUICHE_H3_EVENT_DATA => {
                                    if (@mod(s, 4) == 0) {
                                        const n_read_h3 = quiche.quiche_h3_recv_body(
                                            h3_conn,
                                            conn,
                                            @bitCast(s),
                                            &request.buf,
                                            request.buf.len,
                                        );
                                        request.buf_slice = request.buf[0..@bitCast(n_read_h3)];
                                    }
                                },
                                quiche.QUICHE_H3_EVENT_FINISHED => {
                                    if (@mod(s, 4) == 0) {
                                        _ = try std.posix.sendto(
                                            server_fd,
                                            request.buf_slice,
                                            0,
                                            @ptrCast(&request.from),
                                            request.from.getOsSockLen(),
                                        );
                                    }
                                },
                                quiche.QUICHE_H3_EVENT_GOAWAY => {},
                                quiche.QUICHE_H3_EVENT_RESET => {},
                                quiche.QUICHE_H3_EVENT_PRIORITY_UPDATE => {},
                                else => unreachable,
                            }
                        }
                    }
                },
                event_type.TIMER => {
                    // std.debug.print("timer event\n", .{});
                    quiche.quiche_conn_on_timeout(conn);
                },
            }
            if (quiche.quiche_conn_is_established(conn) and h3_conn == null) {
                h3_conn = quiche.quiche_h3_conn_new_with_transport(conn, h3_conf) orelse return error.h3_conn_create_failed;
            }

            flush_egress(conn, upstream_fd);

            const ns = quiche.quiche_conn_timeout_as_nanos(conn);
            tspec = .{
                .it_value = .{
                    .tv_sec = @as(isize, @bitCast(ns / @as(usize, 1_000_000_000))),
                    .tv_nsec = @as(isize, @bitCast(ns % @as(usize, 1_000_000_000))),
                },
                .it_interval = .{ .tv_sec = 0, .tv_nsec = 0 },
            };
            try std.posix.timerfd_settime(timer_fd, @bitCast(@as(u32, 0)), &tspec, null);
            // std.debug.print("sleeping for {}ns\n", .{ns});
        }
    }
}
