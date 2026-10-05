#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <limits>

namespace fs = std::filesystem;

// ================================
// Protocol constants
// ================================
// Every frame has a 9-byte header:
//   Length      3 bytes
//   Type        1 byte
//   Flags       1 byte
//   Stream ID   4 bytes
constexpr std::size_t FRAME_HEADER_SIZE = 9;

// Frame types
constexpr uint8_t FRAME_REQUEST          = 0x01;
constexpr uint8_t FRAME_RESPONSE_HEADERS = 0x02;
constexpr uint8_t FRAME_RESPONSE_BODY    = 0x03;
constexpr uint8_t FRAME_END              = 0x04;

// Request methods
constexpr uint8_t METHOD_GET = 0x01;

// Status codes
constexpr uint16_t STATUS_OK            = 200;
constexpr uint16_t STATUS_BAD_REQUEST   = 400;
constexpr uint16_t STATUS_NOT_FOUND     = 404;
constexpr uint16_t STATUS_SERVER_ERROR  = 500;

// Maximum payload because Length is 24 bits.
// 2^24 - 1 = 16,777,215
constexpr uint32_t MAX_FRAME_SIZE = 0xFFFFFF;

// =================
// Utility functions
// =================
uint16_t read_u16_be(const uint8_t* data)
{
    return (static_cast<uint16_t>(data[0]) << 8) |
           static_cast<uint16_t>(data[1]);
}

void write_u16_be(std::vector<uint8_t>& output, uint16_t value)
{
    output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    output.push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t read_u24_be(const uint8_t* data)
{
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           static_cast<uint32_t>(data[2]);
}

void write_u24_be(std::vector<uint8_t>& output, uint32_t value)
{
    output.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    output.push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t read_u32_be(const uint8_t* data)
{
    return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) | (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

void write_u32_be(std::vector<uint8_t>& output, uint32_t value)
{
    output.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    output.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    output.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    output.push_back(static_cast<uint8_t>(value & 0xFF));
}

// ====================================
// TCP helper: receive exactly N bytes
// ====================================
bool recv_exact(int socket_fd, uint8_t* buffer, std::size_t amount)
{
    std::size_t received = 0;

    while (received < amount)
    {
        ssize_t result = recv(
            socket_fd,
            buffer + received,
            amount - received,
            0
        );

        if (result == 0)
        {
            // Client closed connection.
            return false;
        }

        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            throw std::runtime_error(
                std::string("recv() failed: ") +
                std::strerror(errno)
            );
        }

        received += static_cast<std::size_t>(result);
    }
    return true;
}

// ===========================
// TCP helper: send all bytes
// ===========================
void send_all(int socket_fd, const uint8_t* data, std::size_t amount)
{
    std::size_t sent = 0;

    while (sent < amount)
    {
        ssize_t result = send(
            socket_fd,
            data + sent,
            amount - sent,
            0
        );

        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            throw std::runtime_error(
                std::string("send() failed: ") +
                std::strerror(errno)
            );
        }
        sent += static_cast<std::size_t>(result);
    }
}

// ==================
// Header name table
// ==================
std::string header_name_from_index(uint8_t index)
{
    switch (index)
    {
        case 0:
            return "host";

        case 1:
            return "content-type";

        case 2:
            return "content-length";

        case 3:
            return "connection";

        case 4:
            return "user-agent";

        case 5:
            return "accept";

        case 6:
            return "date";

        case 7:
            return "server";

        case 8:
            return "cache-control";

        case 9:
            return "content-encoding";

        default:
            throw std::runtime_error("unknown header index");
    }
}


int header_index_from_name(const std::string& name)
{
    if (name == "host")
        return 0;

    if (name == "content-type")
        return 1;

    if (name == "content-length")
        return 2;

    if (name == "connection")
        return 3;

    if (name == "user-agent")
        return 4;

    if (name == "accept")
        return 5;

    if (name == "date")
        return 6;

    if (name == "server")
        return 7;

    if (name == "cache-control")
        return 8;

    if (name == "content-encoding")
        return 9;

    return -1;
}

// ======================
// Header representation
// ======================
struct Header
{
    std::string name;
    std::string value;
};


// ==================
// Encode one header
// ==================
// Known header:
//   1 byte   -> header name index
//   2 bytes  -> value length
//   N bytes  -> value
// Unknown header:
//   FF       -> literal name
//   2 bytes  -> name length
//   N bytes  -> name
//   2 bytes  -> value length
//   N bytes  -> value
void encode_header(std::vector<uint8_t>& output, const Header& header)
{
    int index = header_index_from_name(header.name);

    if (index >= 0)
    {
        // Known header name.
        output.push_back(static_cast<uint8_t>(index));

        if (header.value.size() > 65535)
        {
            throw std::runtime_error("header value too long");
        }

        write_u16_be(output, static_cast<uint16_t>(header.value.size()));

        output.insert(output.end(), header.value.begin(), header.value.end());

        return;
    }

    // Literal header name.
    output.push_back(0xFF);

    if (header.name.size() > 65535 || header.value.size() > 65535)
    {
        throw std::runtime_error("header too long");
    }

    write_u16_be(output, static_cast<uint16_t>(header.name.size()));

    output.insert(output.end(), header.name.begin(), header.name.end());

    write_u16_be(output, static_cast<uint16_t>(header.value.size()));

    output.insert(output.end(), header.value.begin(), header.value.end());
}

// ===============================
// Encode a complete header block
// ===============================
std::vector<uint8_t> encode_headers(const std::vector<Header>& headers)
{
    if (headers.size() > 255)
    {
        throw std::runtime_error("too many headers");
    }

    std::vector<uint8_t> output;
    // Number of headers.
    output.push_back(static_cast<uint8_t>(headers.size()));

    for (const Header& header : headers)
    {
        encode_header(output, header);
    }

    return output;
}

// ======================
// Send a protocol frame
// ======================
void send_frame(int socket_fd, uint8_t frame_type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t>& payload)
{
    if (payload.size() > MAX_FRAME_SIZE)
    {
        throw std::runtime_error("payload too large");
    }
    // Stream ID is only 31 bits.
    if (stream_id & 0x80000000u)
    {
        throw std::runtime_error("stream ID uses reserved bit");
    }

    std::vector<uint8_t> frame;

    frame.reserve(FRAME_HEADER_SIZE + payload.size());

    write_u24_be(frame, static_cast<uint32_t>(payload.size()));

    frame.push_back(frame_type);
    frame.push_back(flags);

    write_u32_be(frame, stream_id);

    frame.insert(frame.end(), payload.begin(), payload.end());

    send_all(socket_fd, frame.data(), frame.size());
}

// ======================
// Send response headers
// ======================
void send_response_headers(int socket_fd, uint32_t stream_id, uint16_t status, const std::vector<Header>& headers)
{
    std::vector<uint8_t> payload;

    write_u16_be(payload, status);

    std::vector<uint8_t> encoded_headers = encode_headers(headers);

    payload.insert(payload.end(), encoded_headers.begin(), encoded_headers.end());

    send_frame(socket_fd, FRAME_RESPONSE_HEADERS, 0, stream_id, payload);
}

// =======================
// Send an error response
// =======================
void send_error(int socket_fd, uint32_t stream_id, uint16_t status)
{
    send_response_headers(socket_fd, stream_id, status, {{"content-length", "0"}, {"server", "observe"}});

    send_frame(socket_fd, FRAME_END, 0, stream_id, {});
}

// ===================
// Guess Content-Type
// ===================
std::string content_type(const fs::path& path)
{
    std::string extension = path.extension().string();

    if (extension == ".html" || extension == ".htm")
    {
        return "text/html";
    }

    if (extension == ".txt")
    {
        return "text/plain";
    }

    if (extension == ".css")
    {
        return "text/css";
    }

    if (extension == ".js")
    {
        return "application/javascript";
    }

    if (extension == ".json")
    {
        return "application/json";
    }

    if (extension == ".jpg" || extension == ".jpeg")
    {
        return "image/jpeg";
    }

    if (extension == ".png")
    {
        return "image/png";
    }

    if (extension == ".gif")
    {
        return "image/gif";
    }

    return "application/octet-stream";
}

// ==============
// Parse request
// ==============
struct Request
{
    uint8_t method;
    std::string path;
    std::vector<Header> headers;
};

Request parse_request(const std::vector<uint8_t>& payload)
{
    Request request;

    std::size_t position = 0;
    // Method
    if (payload.size() < 1)
    {
        throw std::runtime_error("request missing method");
    }

    request.method = payload[position++];

    if (request.method != METHOD_GET)
    {
        throw std::runtime_error("unsupported method");
    }
    // Path length
    if (position + 2 > payload.size())
    {
        throw std::runtime_error("request missing path length");
    }

    uint16_t path_length = read_u16_be(payload.data() + position);

    position += 2;
    // Path
    if (position + path_length > payload.size())
    {
        throw std::runtime_error("path extends beyond request");
    }

    request.path.assign(reinterpret_cast<const char*>(payload.data() + position), path_length);

    position += path_length;
    // Header count
    if (position >= payload.size())
    {
        throw std::runtime_error("missing header count");
    }

    uint8_t header_count = payload[position++];
    // Headers
    for (uint8_t i = 0; i < header_count; ++i)
    {
        if (position >= payload.size())
        {
            throw std::runtime_error("truncated header");
        }

        uint8_t name_index = payload[position++];

        std::string name;
        // Known header
        if (name_index != 0xFF)
        {
            if (name_index >= 10)
            {
                throw std::runtime_error("invalid header index");
            }

            name = header_name_from_index(name_index);
        }
        // Literal header
        else
        {
            if (position + 2 > payload.size())
            {
                throw std::runtime_error("missing literal name length");
            }

            uint16_t name_length = read_u16_be(payload.data() + position);

            position += 2;

            if (position + name_length > payload.size())
            {
                throw std::runtime_error("truncated literal name");
            }

            name.assign(reinterpret_cast<const char*>(payload.data() + position), name_length);

            position += name_length;
        }
        // Value length
        if (position + 2 > payload.size())
        {
            throw std::runtime_error("missing value length");
        }

        uint16_t value_length = read_u16_be(payload.data() + position);

        position += 2;

        if (position + value_length > payload.size())
        {
            throw std::runtime_error("truncated header value");
        }

        std::string value(reinterpret_cast<const char*>(payload.data() + position), value_length);

        position += value_length;

        request.headers.push_back({name, value});
    }
    // Nothing should remain.
    if (position != payload.size())
    {
        throw std::runtime_error("extra bytes after request");
    }
    return request;
}

// =========================================
// Safely map URL path to a file under root
// =========================================
bool find_file(const fs::path& root, const std::string& request_path, fs::path& result)
{
    try
    {
        if (request_path.empty() || request_path[0] != '/')
        {
            return false;
        }

        fs::path relative = request_path.substr(1);

        fs::path root_absolute = fs::weakly_canonical(root);

        fs::path candidate = fs::weakly_canonical(root_absolute / relative);

        // Check that candidate is actually inside root.
        auto root_it = root_absolute.begin();
        auto root_end = root_absolute.end();

        auto candidate_it = candidate.begin();
        auto candidate_end = candidate.end();

        while (root_it != root_end && candidate_it != candidate_end && *root_it == *candidate_it)
        {
            ++root_it;
            ++candidate_it;
        }

        if (root_it != root_end)
        {
            return false;
        }

        result = candidate;

        return true;
    }
    catch (...)
    {
        return false;
    }
}

// ============
// Send a file
// ============
void send_file(int socket_fd, uint32_t stream_id, const fs::path& path)
{
    std::uintmax_t file_size = fs::file_size(path);

    if (file_size > static_cast<std::uintmax_t>(std::numeric_limits<uint64_t>::max()))
    {
        throw std::runtime_error("file too large");
    }

    send_response_headers(
        socket_fd,
        stream_id,
        STATUS_OK,
        {
            {
                "content-length",
                std::to_string(file_size)
            },
            {
                "content-type",
                content_type(path)
            },
            {
                "server",
                "observe"
            }
        }
    );

    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("cannot open file");
    }

    // Send the file in 1 MiB chunks.
    constexpr std::size_t CHUNK_SIZE = 1024 * 1024;

    std::vector<uint8_t> buffer(CHUNK_SIZE);

    while (file)
    {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        std::streamsize bytes_read = file.gcount();

        if (bytes_read > 0)
        {
            std::vector<uint8_t> body(buffer.begin(), buffer.begin() + bytes_read);

            send_frame(socket_fd, FRAME_RESPONSE_BODY, 0, stream_id, body);
        }
    }

    // Tell client response is complete.
    send_frame(socket_fd, FRAME_END, 0, stream_id, {});
}

// =============================
// Handle one client connection
// =============================
void handle_connection(int client_socket, const sockaddr_in& client_address, const fs::path& root)
{
    char client_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &client_address.sin_addr, client_ip, sizeof(client_ip));

    std::cout
        << "Client connected: "
        << client_ip
        << ":"
        << ntohs(client_address.sin_port)
        << '\n';

    try
    {
        while (true)
        {
            // Read 9-byte frame header.
            uint8_t header[FRAME_HEADER_SIZE];

            bool connection_alive = recv_exact(client_socket, header, FRAME_HEADER_SIZE);

            if (!connection_alive)
            {
                break;
            }

            // Decode header.
            uint32_t length = read_u24_be(header);

            uint8_t frame_type = header[3];

            uint8_t flags = header[4];

            uint32_t stream_id = read_u32_be(header + 5);

            // Read payload.
            std::vector<uint8_t> payload(length);

            if (length > 0)
            {
                // Connection closed in the middle of a frame.
                if (!recv_exact(client_socket, payload.data(), length))
                {
                    break;
                }
            }

            if (stream_id & 0x80000000u)
            {
                std::cerr
                    << "Invalid stream ID\n";

                send_error(client_socket, stream_id & 0x7FFFFFFFu, STATUS_BAD_REQUEST);
                continue;
            }

            std::cout
                << "Frame received: "
                << "type=0x"
                << std::hex
                << static_cast<int>(frame_type)
                << std::dec
                << ", length="
                << length
                << ", stream="
                << stream_id
                << ", flags="
                << static_cast<int>(flags)
                << '\n';

            // Unknown frame
            if (frame_type != FRAME_REQUEST)
            {
                std::cout
                    << "Unknown frame type. "
                    << "Skipping it.\n";

                continue;
            }

            // Decode REQUEST
            Request request;

            try
            {
                request = parse_request(payload);
            }
            catch (const std::exception& e)
            {
                std::cerr
                    << "Malformed request: "
                    << e.what()
                    << '\n';

                send_error(client_socket, stream_id, STATUS_BAD_REQUEST);
                continue;
            }

            std::cout
                << "GET "
                << request.path
                << '\n';

            // Convert URL path into safe filesystem path.
            fs::path file_path;

            if (!find_file(root, request.path, file_path))
            {
                std::cerr
                    << "Invalid path: "
                    << request.path
                    << '\n';

                send_error(client_socket, stream_id, STATUS_BAD_REQUEST);
                continue;
            }

            // Check whether file exists
            if (!fs::is_regular_file(file_path))
            {
                std::cout
                    << "File not found: "
                    << file_path
                    << '\n';

                send_error(client_socket, stream_id, STATUS_NOT_FOUND);
                continue;
            }

            // Send requested file
            try
            {
                send_file(client_socket, stream_id, file_path);
            }
            catch (const std::exception& e)
            {
                std::cerr
                    << "File error: "
                    << e.what()
                    << '\n';

                send_error(client_socket, stream_id, STATUS_SERVER_ERROR);
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "Connection error: "
            << e.what()
            << '\n';
    }

    close(client_socket);

    std::cout
        << "Client disconnected.\n";
}

// =======
// main()
// =======

int main(int argc, char* argv[])
{
    // Check arguments.
    if (argc != 3)
    {
        std::cerr
            << "Usage: "
            << argv[0]
            << " ROOT PORT\n";

        return 1;
    }

    fs::path root = argv[1];
    int port;

    try
    {
        port = std::stoi(argv[2]);
    }
    catch (...)
    {
        std::cerr
            << "Invalid port.\n";

        return 1;
    }

    if (port < 1 || port > 65535)
    {
        std::cerr
            << "Port must be between "
            << "1 and 65535.\n";

        return 1;
    }

    if (!fs::is_directory(root))
    {
        std::cerr
            << "Root directory does not exist: "
            << root
            << '\n';

        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    // Create TCP socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket < 0)
    {
        std::cerr
            << "socket() failed: "
            << std::strerror(errno)
            << '\n';

        return 1;
    }

    // Allow immediate restart after stopping server
    int reuse = 1;

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr
            << "setsockopt() failed: "
            << std::strerror(errno)
            << '\n';

        close(server_socket);
        return 1;
    }

    // Create server address
    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    server_address.sin_port = htons(static_cast<uint16_t>(port));

    // Bind
    if (bind(server_socket, reinterpret_cast<sockaddr*>(&server_address), sizeof(server_address)) < 0)
    {
        std::cerr
            << "bind() failed: "
            << std::strerror(errno)
            << '\n';

        close(server_socket);
        return 1;
    }

    // Listen
    if (listen(server_socket, 10) < 0)
    {
        std::cerr
            << "listen() failed: "
            << std::strerror(errno)
            << '\n';

        close(server_socket);
        return 1;
    }

    // Server is ready
    std::cout
        << "====================================\n"
        << " Binary HTTP Server\n"
        << "====================================\n"
        << "Root : "
        << fs::absolute(root)
        << '\n'
        << "Port : "
        << port
        << '\n'
        << "Waiting for clients...\n"
        << "====================================\n";

    // Accept clients forever
    while (true)
    {
        sockaddr_in client_address{};
        socklen_t client_length = sizeof(client_address);

        int client_socket = accept(server_socket, reinterpret_cast<sockaddr*>( &client_address), &client_length);

        if (client_socket < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            std::cerr
                << "accept() failed: "
                << std::strerror(errno)
                << '\n';

            continue;
        }

        handle_connection(client_socket, client_address, root);
    }
    close(server_socket);
    return 0;
}