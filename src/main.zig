const std = @import("std");
const net = std.net;

var directoryArgument: ?[]const u8 = null;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var argIterator = try std.process.argsWithAllocator(allocator);
    defer argIterator.deinit();

    _ = argIterator.skip(); // skip first argument ()
    while (argIterator.next()) |arg| {
        if (std.mem.eql(u8, arg, "--directory")) {

            const dirArg = argIterator.next() orelse {
                std.debug.print("Invalid Directory Argument", .{});
                return;
            };
            directoryArgument = try allocator.dupe(u8, dirArg);
        }
    }

    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    while (true) {
        const connection = listener.accept() catch |err| {
            std.debug.print("{any}", .{err});
            continue;
        };
        _ = std.Thread.spawn(.{}, handleRequest, .{allocator, connection}) catch |err| {
            std.debug.print("unable to spawn connection thread: {s}", .{@errorName(err)});
            connection.stream.close();
            continue;
        };
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

    try routeRequest(allocator, connection, request);
}

pub fn routeRequest(allocator: std.mem.Allocator, connection: std.net.Server.Connection, request: Request) !void {
    const requestLine = request.requestLine;
    var statusLine: StatusLine = undefined;
    var responseBody: ?[]const u8 = null;


    if (std.mem.eql(u8, "/", requestLine.target)) {
        statusLine = StatusLine.ok();

    } else if (std.mem.startsWith(u8, requestLine.target, "/echo/")) {
        const arg = std.mem.trimStart(u8, requestLine.target, "/echo/");
        if (arg.len > 0) {
            statusLine = StatusLine.ok();
            responseBody = arg;
        } else {
            statusLine = StatusLine.badRequest();
        }

    } else if (std.mem.startsWith(u8, requestLine.target, "/user-agent")) {
        const userAgent = request.headers.get("User-Agent");
        if (userAgent != null) {
            statusLine = StatusLine.ok();
            responseBody = userAgent;
        } else {
            statusLine = StatusLine.badRequest();
        }

    } else if (std.mem.startsWith(u8, requestLine.target, "/files/")) {
        const path = std.mem.trimStart(u8, requestLine.target, "/files/");
        if (path.len > 0) {
            responseBody = readFile(allocator, path);
            if (responseBody == null) {
                statusLine = StatusLine.notFound();
            } else {
                statusLine = StatusLine.ok();
            }
        } else {
            statusLine = StatusLine.badRequest();
        }

    } else {
        statusLine = StatusLine.notFound();
    }

    try sendResponse(connection, statusLine, responseBody, std.mem.startsWith(u8, requestLine.target, "/files/")); // TODO refactor to response struct
}

pub fn sendResponse(connection: std.net.Server.Connection, statusLine: StatusLine, body: ?[]const u8, isFile: bool) !void {
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
        if (isFile) {
            try writer.interface.print("Content-Type: application/octet-stream\r\n", .{});
        } else {
            try writer.interface.print("Content-Type: text/plain\r\n", .{});
        }
        try writer.interface.print(
            "Content-Length: {d}\r\n",
            .{body.?.len}
        );
    }
    try writer.interface.print("\r\n", .{});

    // BODY
    if (body != null) {
        try writer.interface.writeAll(body.?);
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

pub fn readFile(allocator: std.mem.Allocator, path: []const u8) ?[]const u8 {
    var dir = std.fs.openDirAbsolute(directoryArgument orelse return null, .{})
        catch return null;
    defer dir.close();

    var file = dir.openFile(path, .{.mode = .read_only}) catch return null;
    defer file.close();

    const fileStat = file.stat() catch return null;
    const fileSize = fileStat.size;

    var reader: std.fs.File.Reader = file.reader(&.{});
    return reader.interface.readAlloc(allocator, fileSize) catch return null;
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

    pub fn ok() StatusLine {
        return .{
            .statusCode = "200",
            .reasonPhrase = "OK",
        };
    }

    pub fn notFound() StatusLine {
        return .{
            .statusCode = "404",
            .reasonPhrase = "Not Found",
        };
    }

    pub fn badRequest() StatusLine {
        return .{
            .statusCode = "400",
            .reasonPhrase = "Bad Request",
        };
    }
};
