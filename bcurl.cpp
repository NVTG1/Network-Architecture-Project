#include <arpa/inet.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>


// ============================================================
// Protocol constants
// ============================================================

constexpr uint8_t FRAME_REQUEST          = 0x01;
constexpr uint8_t FRAME_RESPONSE_HEADERS = 0x02;
constexpr uint8_t FRAME_RESPONSE_BODY    = 0x03;
constexpr uint8_t FRAME_END              = 0x04;

constexpr uint8_t METHOD_GET = 0x01;

constexpr uint32_t STREAM_ID = 1;

constexpr std::size_t FRAME_HEADER_SIZE = 9;


// ============================================================
// Header name indexes
//
// These MUST match server.cpp
// ============================================================

std::string header_name(uint8_t index)
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
            return "unknown";
    }
}


// ============================================================
// Send all bytes
//
// TCP send() is allowed to send fewer bytes than requested.
// Therefore we keep sending until everything is written.
// ============================================================

bool send_all(
    int socket_fd,
    const uint8_t* data,
    std::size_t length)
{
    std::size_t total_sent = 0;

    while (total_sent < length)
    {
        ssize_t sent = send(
            socket_fd,
            data + total_sent,
            length - total_sent,
            0
        );

        if (sent < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            return false;
        }

        if (sent == 0)
        {
            return false;
        }

        total_sent += static_cast<std::size_t>(sent);
    }

    return true;
}


// ============================================================
// Receive exactly N bytes
//
// TCP recv() is allowed to return fewer bytes than requested.
// ============================================================

bool recv_exact(
    int socket_fd,
    uint8_t* data,
    std::size_t length)
{
    std::size_t total_received = 0;

    while (total_received < length)
    {
        ssize_t received = recv(
            socket_fd,
            data + total_received,
            length - total_received,
            0
        );

        if (received < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            return false;
        }

        if (received == 0)
        {
            return false;
        }

        total_received += static_cast<std::size_t>(received);
    }

    return true;
}


// ============================================================
// Big-endian integer helpers
// ============================================================

void write_uint16(
    std::vector<uint8_t>& buffer,
    uint16_t value)
{
    buffer.push_back(
        static_cast<uint8_t>((value >> 8) & 0xFF)
    );

    buffer.push_back(
        static_cast<uint8_t>(value & 0xFF)
    );
}


uint16_t read_uint16(
    const uint8_t* data)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8) |
        static_cast<uint16_t>(data[1])
    );
}


void write_uint24(
    std::vector<uint8_t>& buffer,
    uint32_t value)
{
    buffer.push_back(
        static_cast<uint8_t>((value >> 16) & 0xFF)
    );

    buffer.push_back(
        static_cast<uint8_t>((value >> 8) & 0xFF)
    );

    buffer.push_back(
        static_cast<uint8_t>(value & 0xFF)
    );
}


uint32_t read_uint24(
    const uint8_t* data)
{
    return
        (static_cast<uint32_t>(data[0]) << 16) |
        (static_cast<uint32_t>(data[1]) << 8) |
        static_cast<uint32_t>(data[2]);
}


void write_uint32(
    std::vector<uint8_t>& buffer,
    uint32_t value)
{
    buffer.push_back(
        static_cast<uint8_t>((value >> 24) & 0xFF)
    );

    buffer.push_back(
        static_cast<uint8_t>((value >> 16) & 0xFF)
    );

    buffer.push_back(
        static_cast<uint8_t>((value >> 8) & 0xFF)
    );

    buffer.push_back(
        static_cast<uint8_t>(value & 0xFF)
    );
}


uint32_t read_uint32(
    const uint8_t* data)
{
    return
        (static_cast<uint32_t>(data[0]) << 24) |
        (static_cast<uint32_t>(data[1]) << 16) |
        (static_cast<uint32_t>(data[2]) << 8) |
        static_cast<uint32_t>(data[3]);
}


// ============================================================
// Frame structure
//
// Protocol:
//
// Length      3 bytes
// Type        1 byte
// Flags       1 byte
// Stream ID   4 bytes
// Payload     variable
// ============================================================

struct Frame
{
    uint32_t length = 0;

    uint8_t type = 0;

    uint8_t flags = 0;

    uint32_t stream_id = 0;

    std::vector<uint8_t> payload;
};


// ============================================================
// Send a frame
// ============================================================

bool send_frame(
    int socket_fd,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const std::vector<uint8_t>& payload)
{
    if (payload.size() > 0xFFFFFF)
    {
        std::cerr
            << "Payload is too large.\n";

        return false;
    }

    std::vector<uint8_t> frame;

    frame.reserve(
        FRAME_HEADER_SIZE + payload.size()
    );

    // --------------------------------------------------------
    // Length: 3 bytes
    // --------------------------------------------------------

    write_uint24(
        frame,
        static_cast<uint32_t>(payload.size())
    );

    // --------------------------------------------------------
    // Type
    // --------------------------------------------------------

    frame.push_back(type);

    // --------------------------------------------------------
    // Flags
    // --------------------------------------------------------

    frame.push_back(flags);

    // --------------------------------------------------------
    // Stream ID: 4 bytes
    // --------------------------------------------------------

    write_uint32(
        frame,
        stream_id
    );

    // --------------------------------------------------------
    // Payload
    // --------------------------------------------------------

    frame.insert(
        frame.end(),
        payload.begin(),
        payload.end()
    );

    return send_all(
        socket_fd,
        frame.data(),
        frame.size()
    );
}


// ============================================================
// Receive one frame
// ============================================================

bool receive_frame(
    int socket_fd,
    Frame& frame)
{
    uint8_t header[FRAME_HEADER_SIZE];

    if (!recv_exact(
            socket_fd,
            header,
            FRAME_HEADER_SIZE))
    {
        return false;
    }

    // --------------------------------------------------------
    // Decode frame header
    // --------------------------------------------------------

    frame.length =
        read_uint24(header);

    frame.type =
        header[3];

    frame.flags =
        header[4];

    frame.stream_id =
        read_uint32(header + 5);

    // --------------------------------------------------------
    // Receive payload
    // --------------------------------------------------------

    frame.payload.resize(frame.length);

    if (frame.length > 0)
    {
        if (!recv_exact(
                socket_fd,
                frame.payload.data(),
                frame.length))
        {
            return false;
        }
    }

    return true;
}


// ============================================================
// Build GET request payload
//
// Exact server.cpp format:
//
// Method       1 byte
// Path Length  2 bytes
// Path         N bytes
// Header Count 1 byte
//
// For every header:
//
// Header Name Index 1 byte
// Value Length      2 bytes
// Value             N bytes
// ============================================================

std::vector<uint8_t> make_get_payload(
    const std::string& path,
    const std::string& host)
{
    std::vector<uint8_t> payload;

    // --------------------------------------------------------
    // 1. Method
    // --------------------------------------------------------

    payload.push_back(METHOD_GET);

    // --------------------------------------------------------
    // 2. Path length
    // --------------------------------------------------------

    if (path.size() > 65535)
    {
        throw std::runtime_error(
            "Path is too long"
        );
    }

    write_uint16(
        payload,
        static_cast<uint16_t>(path.size())
    );

    // --------------------------------------------------------
    // 3. Path
    // --------------------------------------------------------

    payload.insert(
        payload.end(),
        path.begin(),
        path.end()
    );

    // --------------------------------------------------------
    // 4. Header count
    //
    // We send exactly one header:
    //
    // host
    // --------------------------------------------------------

    payload.push_back(1);

    // --------------------------------------------------------
    // 5. Header name index
    //
    // server.cpp:
    //
    // 0 = host
    // --------------------------------------------------------

    payload.push_back(0);

    // --------------------------------------------------------
    // 6. Header value length
    // --------------------------------------------------------

    if (host.size() > 65535)
    {
        throw std::runtime_error(
            "Host value is too long"
        );
    }

    write_uint16(
        payload,
        static_cast<uint16_t>(host.size())
    );

    // --------------------------------------------------------
    // 7. Header value
    // --------------------------------------------------------

    payload.insert(
        payload.end(),
        host.begin(),
        host.end()
    );

    return payload;
}


// ============================================================
// Response header
// ============================================================

struct ResponseHeader
{
    std::string name;
    std::string value;
};


// ============================================================
// Decode response headers
//
// IMPORTANT:
// This follows the response format we have currently
// established. If the server's response encoder uses a
// different layout, we will adjust this after testing.
// ============================================================

void decode_response_headers(
    const std::vector<uint8_t>& payload,
    uint16_t& status,
    std::vector<ResponseHeader>& headers)
{
    std::size_t position = 0;

    // --------------------------------------------------------
    // Status code
    // --------------------------------------------------------

    if (position + 2 > payload.size())
    {
        throw std::runtime_error(
            "Response headers missing status"
        );
    }

    status =
        read_uint16(
            payload.data() + position
        );

    position += 2;

    // --------------------------------------------------------
    // Header count
    // --------------------------------------------------------

    if (position >= payload.size())
    {
        throw std::runtime_error(
            "Response headers missing count"
        );
    }

    uint8_t header_count =
        payload[position++];

    headers.clear();

    // --------------------------------------------------------
    // Headers
    // --------------------------------------------------------

    for (uint8_t i = 0;
         i < header_count;
         ++i)
    {
        if (position >= payload.size())
        {
            throw std::runtime_error(
                "Truncated response header"
            );
        }

        uint8_t name_index =
            payload[position++];

        std::string name;

        // ----------------------------------------------------
        // Known header
        // ----------------------------------------------------

        if (name_index != 0xFF)
        {
            if (name_index >= 10)
            {
                throw std::runtime_error(
                    "Invalid response header index"
                );
            }

            name =
                header_name(name_index);
        }

        // ----------------------------------------------------
        // Literal header name
        // ----------------------------------------------------

        else
        {
            if (position + 2 > payload.size())
            {
                throw std::runtime_error(
                    "Missing literal header name length"
                );
            }

            uint16_t name_length =
                read_uint16(
                    payload.data() + position
                );

            position += 2;

            if (position + name_length >
                payload.size())
            {
                throw std::runtime_error(
                    "Truncated literal header name"
                );
            }

            name.assign(
                reinterpret_cast<const char*>(
                    payload.data() + position
                ),
                name_length
            );

            position += name_length;
        }

        // ----------------------------------------------------
        // Value length
        // ----------------------------------------------------

        if (position + 2 > payload.size())
        {
            throw std::runtime_error(
                "Missing response header value length"
            );
        }

        uint16_t value_length =
            read_uint16(
                payload.data() + position
            );

        position += 2;

        // ----------------------------------------------------
        // Value
        // ----------------------------------------------------

        if (position + value_length >
            payload.size())
        {
            throw std::runtime_error(
                "Truncated response header value"
            );
        }

        std::string value(
            reinterpret_cast<const char*>(
                payload.data() + position
            ),
            value_length
        );

        position += value_length;

        headers.push_back(
            {name, value}
        );
    }

    // --------------------------------------------------------
    // No extra bytes should remain
    // --------------------------------------------------------

    if (position != payload.size())
    {
        throw std::runtime_error(
            "Extra bytes after response headers"
        );
    }
}


// ============================================================
// Print response headers
// ============================================================

void print_response_headers(
    uint16_t status,
    const std::vector<ResponseHeader>& headers)
{
    std::cout
        << "\n========== RESPONSE ==========\n";

    std::cout
        << "Status: "
        << status
        << "\n";

    for (const auto& header : headers)
    {
        std::cout
            << header.name
            << ": "
            << header.value
            << "\n";
    }

    std::cout
        << "==============================\n\n";
}


// ============================================================
// Main
// ============================================================

int main(
    int argc,
    char* argv[])
{
    // --------------------------------------------------------
    // Command-line arguments
    // --------------------------------------------------------

    if (argc != 4)
    {
        std::cerr
            << "Usage: "
            << argv[0]
            << " <host> <port> <path>\n";

        std::cerr
            << "Example: "
            << argv[0]
            << " 127.0.0.1 9000 /index.html\n";

        return 1;
    }

    std::string host = argv[1];
    std::string port_string = argv[2];
    std::string path = argv[3];

    int port;

    try
    {
        port =
            std::stoi(port_string);
    }
    catch (...)
    {
        std::cerr
            << "Invalid port: "
            << port_string
            << "\n";

        return 1;
    }

    if (port < 1 || port > 65535)
    {
        std::cerr
            << "Port must be between 1 and 65535.\n";

        return 1;
    }

    if (path.empty() || path[0] != '/')
    {
        std::cerr
            << "Path must start with '/'.\n";

        return 1;
    }


    // --------------------------------------------------------
    // Print request information
    // --------------------------------------------------------

    std::cout
        << "Host : "
        << host
        << "\n";

    std::cout
        << "Port : "
        << port
        << "\n";

    std::cout
        << "Path : "
        << path
        << "\n";


    // --------------------------------------------------------
    // Create TCP socket
    // --------------------------------------------------------

    std::cout
        << "Connecting...\n";

    int socket_fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (socket_fd < 0)
    {
        std::cerr
            << "socket() failed: "
            << std::strerror(errno)
            << "\n";

        return 1;
    }


    // --------------------------------------------------------
    // Server address
    // --------------------------------------------------------

    sockaddr_in server_address{};

    server_address.sin_family =
        AF_INET;

    server_address.sin_port =
        htons(
            static_cast<uint16_t>(port)
        );


    // --------------------------------------------------------
    // Convert IPv4 text to binary
    // --------------------------------------------------------

    if (inet_pton(
            AF_INET,
            host.c_str(),
            &server_address.sin_addr) != 1)
    {
        std::cerr
            << "Invalid IPv4 address: "
            << host
            << "\n";

        close(socket_fd);

        return 1;
    }


    // --------------------------------------------------------
    // Connect
    // --------------------------------------------------------

    if (connect(
            socket_fd,
            reinterpret_cast<sockaddr*>(
                &server_address
            ),
            sizeof(server_address)) < 0)
    {
        std::cerr
            << "connect() failed: "
            << std::strerror(errno)
            << "\n";

        close(socket_fd);

        return 1;
    }

    std::cout
        << "Connected successfully!\n";


    // --------------------------------------------------------
    // Build GET request
    // --------------------------------------------------------

    std::vector<uint8_t> request_payload;

    try
    {
        request_payload =
            make_get_payload(
                path,
                host + ":" +
                std::to_string(port)
            );
    }
    catch (const std::exception& error)
    {
        std::cerr
            << "Failed to build request: "
            << error.what()
            << "\n";

        close(socket_fd);

        return 1;
    }


    // --------------------------------------------------------
    // Send REQUEST frame
    // --------------------------------------------------------

    if (!send_frame(
            socket_fd,
            FRAME_REQUEST,
            0,
            STREAM_ID,
            request_payload))
    {
        std::cerr
            << "Failed to send GET request.\n";

        close(socket_fd);

        return 1;
    }

    std::cout
        << "GET request sent successfully!\n";


    // --------------------------------------------------------
    // Receive response
    // --------------------------------------------------------

    bool response_headers_received = false;

    while (true)
    {
        Frame frame;

        if (!receive_frame(
                socket_fd,
                frame))
        {
            std::cerr
                << "Connection closed while "
                << "waiting for response.\n";

            close(socket_fd);

            return 1;
        }


        // ----------------------------------------------------
        // Check stream
        // ----------------------------------------------------

        if (frame.stream_id != STREAM_ID)
        {
            std::cerr
                << "Warning: received frame for "
                << "unexpected stream "
                << frame.stream_id
                << "\n";

            continue;
        }


        // ----------------------------------------------------
        // RESPONSE_HEADERS
        // ----------------------------------------------------

        if (frame.type ==
            FRAME_RESPONSE_HEADERS)
        {
            uint16_t status = 0;

            std::vector<ResponseHeader> headers;

            try
            {
                decode_response_headers(
                    frame.payload,
                    status,
                    headers
                );
            }
            catch (const std::exception& error)
            {
                std::cerr
                    << "Failed to decode response "
                    << "headers: "
                    << error.what()
                    << "\n";

                close(socket_fd);

                return 1;
            }

            print_response_headers(
                status,
                headers
            );

            response_headers_received = true;
        }


        // ----------------------------------------------------
        // RESPONSE_BODY
        // ----------------------------------------------------

        else if (frame.type ==
                 FRAME_RESPONSE_BODY)
        {
            if (!response_headers_received)
            {
                std::cerr
                    << "Warning: received body "
                    << "before headers.\n";
            }

            if (!frame.payload.empty())
            {
                std::cout.write(
                    reinterpret_cast<const char*>(
                        frame.payload.data()
                    ),
                    static_cast<std::streamsize>(
                        frame.payload.size()
                    )
                );

                std::cout.flush();
            }
        }


        // ----------------------------------------------------
        // END
        // ----------------------------------------------------

        else if (frame.type ==
                 FRAME_END)
        {
            std::cout
                << "\n\nResponse complete.\n";

            break;
        }


        // ----------------------------------------------------
        // Unknown frame
        // ----------------------------------------------------

        else
        {
            std::cerr
                << "Warning: unknown frame type 0x"
                << std::hex
                << static_cast<int>(frame.type)
                << std::dec
                << "\n";
        }
    }


    // --------------------------------------------------------
    // Close connection
    // --------------------------------------------------------

    close(socket_fd);

    return 0;
}