#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// Protocol constants
constexpr std::size_t FRAME_HEADER_SIZE = 9;

constexpr uint8_t FRAME_REQUEST          = 0x01;
constexpr uint8_t FRAME_RESPONSE_HEADERS = 0x02;
constexpr uint8_t FRAME_RESPONSE_BODY    = 0x03;
constexpr uint8_t FRAME_END              = 0x04;

constexpr uint8_t METHOD_GET = 0x01;
constexpr uint32_t STREAM_ID = 1;

// Ten predefined header names.
static const char* HEADER_NAMES[10] = {
    "host",
    "content-type",
    "content-length",
    "connection",
    "user-agent",
    "accept",
    "date",
    "server",
    "cache-control",
    "content-encoding"
};

bool g_verbose = false;

// Big-endian helpers
void put16(std::vector<uint8_t>& b, uint16_t v)
{
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put24(std::vector<uint8_t>& b, uint32_t v)
{
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put32(std::vector<uint8_t>& b, uint32_t v)
{
    b.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint16_t get16(const uint8_t* d)
{
    return (static_cast<uint16_t>(d[0]) << 8) |
           static_cast<uint16_t>(d[1]);
}

uint32_t get24(const uint8_t* d)
{
    return (static_cast<uint32_t>(d[0]) << 16) |
           (static_cast<uint32_t>(d[1]) << 8) |
           static_cast<uint32_t>(d[2]);
}

uint32_t get32(const uint8_t* d)
{
    return (static_cast<uint32_t>(d[0]) << 24) |
           (static_cast<uint32_t>(d[1]) << 16) |
           (static_cast<uint32_t>(d[2]) << 8) |
           static_cast<uint32_t>(d[3]);
}

// TCP helpers
bool send_all(int fd, const uint8_t* data, std::size_t n)
{
    std::size_t sent = 0;

    while (sent < n)
    {
        ssize_t r = send(fd, data + sent, n - sent, 0);

        if (r < 0)
        {
            if (errno == EINTR)
                continue;

            return false;
        }

        if (r == 0)
            return false;

        sent += static_cast<std::size_t>(r);
    }

    return true;
}

bool recv_exact(int fd, uint8_t* data, std::size_t n)
{
    std::size_t got = 0;

    while (got < n)
    {
        ssize_t r = recv(fd, data + got, n - got, 0);

        if (r < 0)
        {
            if (errno == EINTR)
                continue;

            return false;
        }

        if (r == 0)
            return false;

        got += static_cast<std::size_t>(r);
    }

    return true;
}

// Verbose hexdump
const char* frame_type_name(uint8_t t)
{
    switch (t)
    {
        case FRAME_REQUEST:
            return "REQUEST";

        case FRAME_RESPONSE_HEADERS:
            return "RESPONSE_HEADERS";

        case FRAME_RESPONSE_BODY:
            return "RESPONSE_BODY";

        case FRAME_END:
            return "END";

        default:
            return "UNKNOWN";
    }
}

void hexdump(const uint8_t* data, std::size_t n)
{
    for (std::size_t off = 0; off < n; off += 16)
    {
        fprintf(stderr, "  %04zx  ", off);

        for (std::size_t i = 0; i < 16; ++i)
        {
            if (off + i < n)
                fprintf(stderr, "%02x ", data[off + i]);
            else
                fprintf(stderr, "   ");

            if (i == 7)
                fprintf(stderr, " ");
        }

        fprintf(stderr, " |");

        for (std::size_t i = 0;
             i < 16 && off + i < n;
             ++i)
        {
            uint8_t c = data[off + i];

            fputc(
                (c >= 32 && c < 127) ? c : '.',
                stderr
            );
        }

        fprintf(stderr, "|\n");
    }
}

void dump_frame(
    const char* direction,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const std::vector<uint8_t>& payload)
{
    if (!g_verbose)
        return;

    fprintf(
        stderr,
        "%s %s  length=%zu type=0x%02x flags=0x%02x stream=%u\n",
        direction,
        frame_type_name(type),
        payload.size(),
        type,
        flags,
        stream_id
    );

    std::vector<uint8_t> raw;

    put24(
        raw,
        static_cast<uint32_t>(payload.size())
    );

    raw.push_back(type);
    raw.push_back(flags);

    put32(raw, stream_id);

    const std::size_t MAX_DUMP = 256;

    std::size_t shown =
        payload.size() < MAX_DUMP
            ? payload.size()
            : MAX_DUMP;

    raw.insert(
        raw.end(),
        payload.begin(),
        payload.begin() + shown
    );

    hexdump(raw.data(), raw.size());

    if (shown < payload.size())
    {
        fprintf(
            stderr,
            "  ... (%zu more payload bytes not shown)\n",
            payload.size() - shown
        );
    }

    fprintf(stderr, "\n");
}

// Frame structure
struct Frame
{
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    std::vector<uint8_t> payload;
};

// Send frame
bool send_frame(
    int fd,
    uint8_t type,
    uint8_t flags,
    uint32_t stream_id,
    const std::vector<uint8_t>& payload)
{
    if (payload.size() > 0xFFFFFF)
        return false;

    // Stream ID is only 31 bits.
    if (stream_id & 0x80000000u)
        return false;

    std::vector<uint8_t> frame;

    frame.reserve(
        FRAME_HEADER_SIZE + payload.size()
    );

    put24(
        frame,
        static_cast<uint32_t>(payload.size())
    );

    frame.push_back(type);
    frame.push_back(flags);

    put32(frame, stream_id);

    frame.insert(
        frame.end(),
        payload.begin(),
        payload.end()
    );

    dump_frame(
        "-->",
        type,
        flags,
        stream_id,
        payload
    );

    return send_all(
        fd,
        frame.data(),
        frame.size()
    );
}

// Receive frame
bool receive_frame(int fd, Frame& f)
{
    uint8_t h[FRAME_HEADER_SIZE];

    if (!recv_exact(
            fd,
            h,
            FRAME_HEADER_SIZE))
    {
        return false;
    }

    uint32_t length = get24(h);

    f.type = h[3];
    f.flags = h[4];

    f.stream_id = get32(h + 5);

    f.payload.resize(length);

    if (length > 0)
    {
        if (!recv_exact(
                fd,
                f.payload.data(),
                length))
        {
            return false;
        }
    }

    dump_frame(
        "<--",
        f.type,
        f.flags,
        f.stream_id,
        f.payload
    );

    return true;
}

// Request header helper
void put_header(
    std::vector<uint8_t>& b,
    uint8_t index,
    const std::string& value)
{
    if (value.size() > 65535)
        throw std::runtime_error(
            "header value too long"
        );

    b.push_back(index);

    put16(
        b,
        static_cast<uint16_t>(value.size())
    );

    b.insert(
        b.end(),
        value.begin(),
        value.end()
    );
}

// Build request
std::vector<uint8_t> make_request(
    const std::string& path,
    const std::string& host_header)
{
    if (path.size() > 65535)
        throw std::runtime_error(
            "path too long"
        );

    std::vector<uint8_t> p;

    // GET
    p.push_back(METHOD_GET);

    // Path length
    put16(
        p,
        static_cast<uint16_t>(path.size())
    );

    // Path
    p.insert(
        p.end(),
        path.begin(),
        path.end()
    );

    // Two headers.
    p.push_back(2);

    // Host
    put_header(
        p,
        0,
        host_header
    );

    // User-Agent
    put_header(
        p,
        4,
        "bcurl/1.0"
    );

    return p;
}

// Response headers
struct RespHeader
{
    std::string name;
    std::string value;
};

uint16_t decode_response_headers(
    const std::vector<uint8_t>& p,
    std::vector<RespHeader>& out)
{
    std::size_t pos = 0;

    auto need = [&](std::size_t n)
    {
        if (pos + n > p.size())
        {
            throw std::runtime_error(
                "truncated headers frame"
            );
        }
    };

    // Status + header count.
    need(3);

    uint16_t status =
        get16(p.data());

    pos = 2;

    uint8_t count =
        p[pos++];

    for (uint8_t i = 0;
         i < count;
         ++i)
    {
        need(1);

        uint8_t idx =
            p[pos++];

        std::string name;

        // Literal header name.
        if (idx == 0xFF)
        {
            need(2);

            uint16_t nl =
                get16(p.data() + pos);

            pos += 2;

            need(nl);

            name.assign(
                reinterpret_cast<const char*>(
                    p.data() + pos
                ),
                nl
            );

            pos += nl;
        }

        // Known header name.
        else if (idx < 10)
        {
            name = HEADER_NAMES[idx];
        }

        else
        {
            throw std::runtime_error(
                "invalid header index"
            );
        }

        // Value length.
        need(2);

        uint16_t vl =
            get16(p.data() + pos);

        pos += 2;

        need(vl);

        std::string value(
            reinterpret_cast<const char*>(
                p.data() + pos
            ),
            vl
        );

        pos += vl;

        out.push_back(
            {name, value}
        );
    }

    // Nothing should remain.
    if (pos != p.size())
    {
        throw std::runtime_error(
            "extra bytes in response headers"
        );
    }

    return status;
}

// Parse host:port/path
bool parse_url(
    std::string url,
    std::string& host,
    std::string& port,
    std::string& path)
{
    const std::string scheme = "http://";

    if (url.compare(
            0,
            scheme.size(),
            scheme) == 0)
    {
        url.erase(
            0,
            scheme.size()
        );
    }

    std::size_t slash =
        url.find('/');

    std::string authority =
        (slash == std::string::npos)
            ? url
            : url.substr(0, slash);

    path =
        (slash == std::string::npos)
            ? "/"
            : url.substr(slash);

    if (authority.empty())
        return false;

    std::size_t colon =
        authority.rfind(':');

    if (colon == std::string::npos)
    {
        host = authority;
        port = "80";
    }
    else
    {
        host =
            authority.substr(
                0,
                colon
            );

        port =
            authority.substr(
                colon + 1
            );
    }

    return !host.empty() &&
           !port.empty();
}

// Connect
int connect_to(
    const std::string& host,
    const std::string& port)
{
    addrinfo hints{};

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;

    int rc =
        getaddrinfo(
            host.c_str(),
            port.c_str(),
            &hints,
            &res
        );

    if (rc != 0)
    {
        std::cerr
            << "bcurl: cannot resolve "
            << host
            << ": "
            << gai_strerror(rc)
            << "\n";

        return -1;
    }

    int fd = -1;

    for (addrinfo* ai = res;
         ai != nullptr;
         ai = ai->ai_next)
    {
        fd =
            socket(
                ai->ai_family,
                ai->ai_socktype,
                ai->ai_protocol
            );

        if (fd < 0)
            continue;

        if (connect(
                fd,
                ai->ai_addr,
                ai->ai_addrlen) == 0)
        {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0)
    {
        std::cerr
            << "bcurl: cannot connect to "
            << host
            << ":"
            << port
            << "\n";
    }

    return fd;
}

// Main
int main(
    int argc,
    char* argv[])
{
    std::string url;

    for (int i = 1;
         i < argc;
         ++i)
    {
        std::string a = argv[i];

        if (a == "-v")
        {
            g_verbose = true;
        }
        else if (url.empty())
        {
            url = a;
        }
        else
        {
            url.clear();
            break;
        }
    }

    std::string host;
    std::string port;
    std::string path;

    if (url.empty() ||
        !parse_url(
            url,
            host,
            port,
            path))
    {
        std::cerr
            << "Usage: "
            << argv[0]
            << " [-v] host:port/path\n"
            << "Example: "
            << argv[0]
            << " -v localhost:9000/index.html\n";

        return 2;
    }

    int fd =
        connect_to(
            host,
            port
        );

    if (fd < 0)
        return 2;

    // Send exactly one request frame.
    try
    {
        std::vector<uint8_t> req =
            make_request(
                path,
                host + ":" + port
            );

        if (!send_frame(
                fd,
                FRAME_REQUEST,
                0,
                STREAM_ID,
                req))
        {
            std::cerr
                << "bcurl: failed to send request\n";

            close(fd);
            return 2;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "bcurl: "
            << e.what()
            << "\n";

        close(fd);
        return 2;
    }

    // Read response on same connection.
    bool got_headers = false;
    uint16_t status = 0;

    while (true)
    {
        Frame f;

        if (!receive_frame(
                fd,
                f))
        {
            std::cerr
                << "bcurl: connection closed before "
                   "response completed\n";

            close(fd);
            return 2;
        }

        // Reserved stream-ID bit.
        // The top bit must be zero.
        if (f.stream_id & 0x80000000u)
        {
            std::cerr
                << "bcurl: response uses reserved "
                   "stream-id bit\n";

            close(fd);
            return 2;
        }

        // Ignore frames belonging to another stream.
        if (f.stream_id != STREAM_ID)
            continue;

        // Response headers.
        if (f.type == FRAME_RESPONSE_HEADERS)
        {
            std::vector<RespHeader> headers;

            try
            {
                status =
                    decode_response_headers(
                        f.payload,
                        headers
                    );
            }
            catch (const std::exception& e)
            {
                std::cerr
                    << "bcurl: bad response headers: "
                    << e.what()
                    << "\n";

                close(fd);
                return 2;
            }

            got_headers = true;

            if (g_verbose)
            {
                fprintf(
                    stderr,
                    "status: %u\n",
                    status
                );

                for (const auto& h : headers)
                {
                    fprintf(
                        stderr,
                        "%s: %s\n",
                        h.name.c_str(),
                        h.value.c_str()
                    );
                }

                fprintf(
                    stderr,
                    "\n"
                );
            }
        }

        // Response body.
        else if (f.type == FRAME_RESPONSE_BODY)
        {
            if (!got_headers)
            {
                std::cerr
                    << "bcurl: body arrived before headers\n";

                close(fd);
                return 2;
            }

            // Body only goes to stdout.
            fwrite(
                f.payload.data(),
                1,
                f.payload.size(),
                stdout
            );
        }

        // End frame.
        else if (f.type == FRAME_END)
        {
            break;
        }

        // Unknown frame.
        else
        {
            if (g_verbose)
            {
                fprintf(
                    stderr,
                    "(skipping unknown frame type "
                    "0x%02x)\n\n",
                    f.type
                );
            }
        }
    }

    fflush(stdout);

    close(fd);

    if (!got_headers)
    {
        std::cerr
            << "bcurl: response had no headers\n";

        return 2;
    }

    // 4xx / 5xx => non-zero.
    if (status >= 400)
        return 1;

    return 0;
}