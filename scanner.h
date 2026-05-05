// scanner.h - Header file for the port scanner implementation

#pragma once

#include <string>
#include <vector>

enum class PortState { 
    OPEN,
    CLOSED,
    FILTERED
};

struct ScanResult {
    int port;
    PortState state;
    std::string service;
    // -v part
    std::string banner; 
};

std::string grabBanner(const std::string& target, int port);
ScanResult scanPort(const std::string& target, int port, bool verbose);
std::vector<ScanResult> scanRange(const std::string& target, int startPort, int endPort, int numThreads, bool verbose);
std::vector<int> getTopPorts(int n);
std::vector<ScanResult> For_TargPorts(const std::string& target, const std::vector<int>& ports, int numThreads, bool verbose);