const std = @import("std");
const net = std.net;

pub fn main() !void {
    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    const connection = try listener.accept();
    try handleRequest(connection);
}

pub fn handleRequest(connection: std.net.Server.Connection) !void {
    defer connection.stream.close();

    var requestBuffer: [1024]u8 = undefined;
    var reader = connection.stream.reader(&requestBuffer);
    const interface: *std.Io.Reader = reader.interface();
    const firstLine = try interface.takeDelimiterInclusive('\n');

    const requestLine = try parseRequestLine(firstLine);

    var statusLine: StatusLine = undefined;
    if (std.mem.eql(u8, "/", requestLine.target)) {
        statusLine = StatusLine{
            .statusCode = "200",
            .reasonPhrase = "OK"
        };
    } else {
        statusLine = StatusLine{
            .statusCode = "404",
            .reasonPhrase = "Not Found"
        };
    }
    try sendResponse(connection, statusLine);
}

pub fn sendResponse(connection: std.net.Server.Connection, statusLine: StatusLine) !void {
    var responseBuffer: [1024]u8 = undefined;
    var writer = connection.stream.writer(&responseBuffer);

    try writer.interface.print("{s} {s} {s}\r\n\r\n", .{
        statusLine.version,
        statusLine.statusCode,
        statusLine.version,
    });

    try writer.interface.flush();
}

pub fn parseRequestLine(line: []const u8) !RequestLine {
    const trimmedLine = std.mem.trim(u8, line, " \r\n");
    if (trimmedLine.len < 1) {
        return RequestLineError.RequestLineMissing;
    }

    var requestLine: RequestLine = undefined;

    var iterator = std.mem.splitScalar(u8, trimmedLine, ' ');

    requestLine.method = std.meta.stringToEnum(
        HttpMethod,
        iterator.next() orelse return RequestLineError.InvalidMethod
    ) orelse return RequestLineError.InvalidMethod;

    requestLine.target = iterator.next() // TODO handle different request targets (https://datatracker.ietf.org/doc/html/rfc9112#section-3.2)
        orelse return error.InvalidTarget;

    requestLine.version = iterator.next()
        orelse return error.InvalidVersion; // TODO validate version

    if (iterator.next() != null) {
        return RequestLineError.ParseError;
    }

    return requestLine;
}

const RequestLine = struct {
    method: HttpMethod,
    target: []const u8,
    version: []const u8,
};

const HttpMethod = enum {
    GET,
};

const RequestLineError = error {
    RequestLineMissing,
    InvalidMethod,
    InvalidTarget,
    InvalidVersion,
    ParseError,
};

const StatusLine = struct {
    version: []const u8 = "HTTP/1.1",
    statusCode: []const u8,
    reasonPhrase: ?[]const u8 = null,
};
