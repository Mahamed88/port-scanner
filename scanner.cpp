#include "scanner.h"
#include "threadpool.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <mutex>
#include <string>
#include <netdb.h>

std::string getServiceName(int port) { 
    struct servent* service = getservbyport(htons(port), "tcp"); 
    if (service != nullptr) {
        return service->s_name;
    }
    return "unknown";
}

std::vector<int> getTopPorts(int n) {
    // ordered by real-world frequency — same order Nmap uses
    std::vector<int> topPorts = {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
        10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646
    };

    if (n > (int)topPorts.size()) n = topPorts.size();
    return std::vector<int>(topPorts.begin(), topPorts.begin() + n);
}
std::vector<ScanResult> For_TargPorts(const std::string& target, const std::vector<int>& ports, int numThreads, bool verbose) {
    std::vector<ScanResult> results;
    std::mutex resultsMutex;

    ThreadPool pool(numThreads);

    for (int port : ports) {
        pool.enqueue([&resultsMutex, &results, &target, port, verbose]() {
            ScanResult result = scanPort(target, port, verbose);
            std::lock_guard<std::mutex> lock(resultsMutex);
            results.push_back(result);
        });
    }

    return results;
}

ScanResult scanPort(const std::string& target, int port, bool verbose) {
    ScanResult result;
    result.port = port;
    result.service = getServiceName(port);
    result.state = PortState::FILTERED;
    result.banner = "";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return result;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(target.c_str());

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    int selectResult = select(sock + 1, NULL, &fdset, NULL, &tv);

    if (selectResult == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            result.state = PortState::OPEN;
            if (verbose) {
                result.banner = grabBanner(target, port);
            }
        } else {
            result.state = PortState::CLOSED;
        }
    } else {
        result.state = PortState::FILTERED;
    }

    close(sock);
    return result;
}

std::vector<ScanResult> scanRange(const std::string& target, int startPort, int endPort, int numThreads, bool verbose) {
    std::vector<ScanResult> results;
    std::mutex resultsMutex;

    ThreadPool pool(numThreads);

    for (int port = startPort; port <= endPort; port++) {
        pool.enqueue([&resultsMutex, &results, &target, port, verbose]() {
            ScanResult result = scanPort(target, port, verbose);
            std::lock_guard<std::mutex> lock(resultsMutex);
            results.push_back(result);
        });
    }

    return results;
}

std::string grabBanner(const std::string& target, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(target.c_str());

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return "";
    }

    // send a generic probe to trigger a response
    const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
    send(sock, probe, strlen(probe), 0);

    char buffer[256] = {0};
    ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    close(sock);

    if (bytes > 0) {
        std::string banner(buffer, bytes);
        // strip newlines and trim to first line
        size_t newline = banner.find_first_of("\r\n");
        if (newline != std::string::npos) {
            banner = banner.substr(0, newline);
        }
        return banner;
    }

    return "(no response)";
}