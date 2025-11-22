const std = @import("std");
const net = std.net;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    // TODO learn and use threads
    while (true) {
        const connection = listener.accept() catch |err| {
            std.debug.print("{any}", .{err});
            continue;
        };
        try handleRequest(allocator, connection);
    }
}

pub fn handleRequest(global_allocator: std.mem.Allocator, connection: std.net.Server.Connection) !void {
    var arena: std.heap.ArenaAllocator = .init(global_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    defer connection.stream.close();

    var requestBuffer: [1024]u8 = undefined;
    var reader = connection.stream.reader(&requestBuffer);
    const interface: *std.Io.Reader = reader.interface();

    const firstLine = try interface.takeDelimiterInclusive('\n');

    // TODO refactor request initialization
    var request: Request = .{
        .requestLine = try parseRequestLine(firstLine),
        .headers = .init(allocator),
    };

    while (interface.takeDelimiterInclusive('\n')) |line| {
        if (line.len <= 2) { // empty line "\r\n" - end of headers
            break;
        }

        var splitLine = std.mem.splitScalar(u8, line, ':');
        const key = splitLine.first(); // TODO case insensitive?
        if (key[key.len - 1] == ' ' or key[0] == ' ') return HeaderError.MalformedHeader;
        const value = std.mem.trim(u8, splitLine.rest(), " \r\n");
        try request.headers.put(key, value);
    } else |err| switch (err) {
        std.Io.Reader.DelimiterError.EndOfStream => {
            std.debug.print("Client closed connection", .{});
            return err;
        },
        else => {
            std.debug.print("{any}", .{err});
            return err;
        }
    }

    try routeRequest(connection, request);
}

pub fn routeRequest(connection: std.net.Server.Connection, request: Request) !void {
    const requestLine = request.requestLine;
    var statusLine: StatusLine = StatusLine{
            .statusCode = "200",
            .reasonPhrase = "OK"
        };
    var responseBody: ?[]const u8 = null;


    if (std.mem.eql(u8, "/", requestLine.target)) {
        // OK
    } else if (std.mem.startsWith(u8, requestLine.target, "/echo/")) {
        const arg = std.mem.trimStart(u8, requestLine.target, "/echo/");
        if (arg.len > 0) {
            // OK
            responseBody = arg;
        } else {
            statusLine = StatusLine{
                .statusCode = "400",
                .reasonPhrase = "Bad Request",
            };
        }
    } else if (std.mem.startsWith(u8, requestLine.target, "/user-agent")) {
        const userAgent = request.headers.get("User-Agent");
        if (userAgent != null) {
            // OK
            responseBody = userAgent;
        } else {
            statusLine = StatusLine{
                .statusCode = "400",
                .reasonPhrase = "Not Found"
            };
        }
    } else {
        statusLine = StatusLine{
            .statusCode = "404",
            .reasonPhrase = "Not Found"
        };
    }
    try sendResponse(connection, statusLine, responseBody);
}

pub fn sendResponse(connection: std.net.Server.Connection, statusLine: StatusLine, body: ?[]const u8) !void {
    var responseBuffer: [1024]u8 = undefined;
    var writer = connection.stream.writer(&responseBuffer);

    // STATUS LINE
    try writer.interface.print("{s} {s}", .{
        statusLine.version,
        statusLine.statusCode,
    });
    if (statusLine.reasonPhrase != null) {
        try writer.interface.print(" {s}", .{statusLine.reasonPhrase.?});
    }
    try writer.interface.print("\r\n", .{});

    // HEADERS
    if (body != null) {
        try writer.interface.print(
            "Content-Type: text/plain\r\n" ++
            "Content-Length: {d}\r\n",
            .{body.?.len}
        );
    }
    try writer.interface.print("\r\n", .{});

    // BODY
    if (body != null) {
        try writer.interface.print("{s}", .{body.?});
    }

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

const Request = struct {
    requestLine: RequestLine,
    headers: std.StringHashMap([]const u8),
    // body: ?[]const u8,
};

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

const HeaderError = error {
    MalformedHeader,
};

const StatusLine = struct {
    version: []const u8 = "HTTP/1.1",
    statusCode: []const u8,
    reasonPhrase: ?[]const u8 = null,
};
