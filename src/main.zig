const std = @import("std");
const net = std.net;

pub fn main() !void {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std.debug.print("Logs from your program will appear here!\n", .{});

    // TODO: Uncomment the code below to pass the first stage
    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    const connection = try listener.accept();

    var connectionStream = connection.stream;
    defer connectionStream.close();

    var responseBuffer: [1024]u8 = undefined;

    var writer = connectionStream.writer(&responseBuffer);

    try writer.interface.print("HTTP/1.1 200 OK\r\n\r\n", .{});
    try writer.interface.flush();

    std.debug.print("client connected!\n", .{});
}
