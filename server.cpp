#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <queue>

// Base64 encoding function
// Using code from user szmoore
std::string base64_encode(const unsigned char* data, size_t len) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    for (size_t pos = 0; pos < len; pos++) {
        char_array_3[i++] = data[pos];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                result += base64_chars[char_array_4[i]];

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            result += base64_chars[char_array_4[j]];

        while (i++ < 3)
            result += '=';
    }

    return result;
}

// Parse HTTP headers
std::unordered_map<std::string, std::string> parse_headers(const std::string& request) {
    std::unordered_map<std::string, std::string> headers;
    std::istringstream stream(request);
    std::string line;

    // Skip request line
    std::getline(stream, line);

    // Parse headers
    while (std::getline(stream, line) && line != "\r") {
        size_t colon = line.find(":");
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            key.erase(key.find_last_not_of(" \t\r\n") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r\n") + 1);
            headers[key] = value;
        }
    }

    return headers;
}

// WebSocket handshake
void perform_websocket_handshake(int client_fd) {
    char buffer[1024] = {0};
    recv(client_fd, buffer, sizeof(buffer), 0);

    std::string request(buffer);
    auto headers = parse_headers(request);

    // Check for WebSocket upgrade
    if (headers["Upgrade"] != "websocket") {
        close(client_fd);
        return;
    }

    std::string sec_websocket_key = headers["Sec-WebSocket-Key"];
    std::string magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    sec_websocket_key += magic_string;

    // Compute SHA-1 hash
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(sec_websocket_key.c_str()), sec_websocket_key.length(), hash);

    // Base64 encode the hash
    std::string accept_key = base64_encode(hash, SHA_DIGEST_LENGTH);

    // Build WebSocket handshake response
    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n"
             << "Upgrade: websocket\r\n"
             << "Connection: Upgrade\r\n"
             << "Sec-WebSocket-Accept: " << accept_key << "\r\n\r\n";

    send(client_fd, response.str().c_str(), response.str().length(), 0);
}

// Send WebSocket frames
void send_websocket_message(int client_fd, const std::string& message) {
    // Check if message is a valid color (not a JSON string)
    std::string json_message = "{\"type\":\"color\", \"data\":" + message + "}";

    std::vector<unsigned char> frame;
    frame.push_back(0x81); // FIN + Text Frame opcode
    if (json_message.size() <= 125) {
        frame.push_back(static_cast<unsigned char>(json_message.size()));
    } else if (json_message.size() <= 65535) {
        frame.push_back(126);
        frame.push_back((json_message.size() >> 8) & 0xFF);
        frame.push_back(json_message.size() & 0xFF);
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) {
            frame.push_back((json_message.size() >> (i * 8)) & 0xFF);
        }
    }
    frame.insert(frame.end(), json_message.begin(), json_message.end());
    send(client_fd, frame.data(), frame.size(), 0);
}

// Read WebSocket frames
std::string read_websocket_message(int client_fd) {
    unsigned char header[2];
    recv(client_fd, header, 2, 0);

    int payload_length = header[1] & 0x7F;
    if (payload_length == 126) {
        unsigned char extended[2];
        recv(client_fd, extended, 2, 0);
        payload_length = (extended[0] << 8) | extended[1];
    } else if (payload_length == 127) {
        unsigned char extended[8];
        recv(client_fd, extended, 8, 0);
        payload_length = 0;
        for (int i = 0; i < 8; ++i) {
            payload_length = (payload_length << 8) | extended[i];
        }
    }

    unsigned char masking_key[4];
    recv(client_fd, masking_key, 4, 0);

    std::vector<unsigned char> payload(payload_length);
    recv(client_fd, payload.data(), payload_length, 0);

    for (int i = 0; i < payload_length; ++i) {
        payload[i] ^= masking_key[i % 4];
    }

    return std::string(payload.begin(), payload.end());
}

// Handle a single client connection
void handle_client(int client_fd, int& other_client_fd, std::mutex& mutex) {
    perform_websocket_handshake(client_fd);

    while (true) {
        try {
            std::string message = read_websocket_message(client_fd);
            std::cout << "Received: " << message << std::endl;

            // Relay the message to the other client
            std::lock_guard<std::mutex> lock(mutex);
            if (other_client_fd != -1) {
                send_websocket_message(other_client_fd, message);
            }
        } catch (...) {
            std::cout << "Client disconnected.\n";
            break;
        }
    }

    close(client_fd);
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (other_client_fd != client_fd) {
            other_client_fd = -1;
        }
    }
}

// Main server function
int main() {
    const int PORT = 8080;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        return 1;
    }

    if (listen(server_fd, 2) == -1) {
        perror("Listen failed");
        return 1;
    }

    std::cout << "Server is running on port " << PORT << "...\n";

    int client1_fd = -1, client2_fd = -1;
    std::mutex mutex;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        std::cout << "New connection accepted.\n";

        std::lock_guard<std::mutex> lock(mutex);
        if (client1_fd == -1) {
            client1_fd = client_fd;
            std::thread(handle_client, client_fd, std::ref(client2_fd), std::ref(mutex)).detach();
        } else if (client2_fd == -1) {
            client2_fd = client_fd;
            std::thread(handle_client, client_fd, std::ref(client1_fd), std::ref(mutex)).detach();
        } else {
            std::cout << "Too many clients connected. Closing connection.\n";
            close(client_fd);
        }
    }

    return 0;
}
