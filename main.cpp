// main.cpp - Entry point for the port scanner

#include "scanner.h"

#include <iostream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <fstream>

using namespace std;

const string RED     = "\033[31m";
const string GREEN   = "\033[32m";
const string YELLOW  = "\033[33m";
const string RESET   = "\033[0m";

void printJSON(const vector<ScanResult>& results, const string& target, double duration) {
    cout << "{\n";
    cout << "  \"target\": \"" << target << "\",\n";
    cout << "  \"duration_ms\": " << (int)(duration * 1000) << ",\n";
    cout << "  \"results\": [\n";

    bool first = true;
    for (const auto& r : results) {
        if (r.state != PortState::OPEN && r.service == "unknown") continue;
        string stateStr;
        switch (r.state) {
            case PortState::OPEN:     stateStr = "open";     break;
            case PortState::CLOSED:   stateStr = "closed";   break;
            case PortState::FILTERED: stateStr = "filtered"; break;
        }

        if (!first) cout << ",\n";
        first = false;

        cout << "    {"
             << " \"port\": " << r.port << ","
             << " \"proto\": \"tcp\","
             << " \"state\": \"" << stateStr << "\","
             << " \"service\": \"" << r.service << "\","
             << " \"banner\": " << (r.banner.empty() ? "null" : "\"" + r.banner + "\"")
             << " }";
    }

    cout << "\n  ],\n";

    int open = 0, closed = 0, filtered = 0;
    for (const auto& r : results) {
        if (r.state == PortState::OPEN)     open++;
        if (r.state == PortState::CLOSED)   closed++;
        if (r.state == PortState::FILTERED) filtered++;
    }

    cout << "  \"summary\": {"
         << " \"open\": " << open << ","
         << " \"closed\": " << closed << ","
         << " \"filtered\": " << filtered
         << " }\n";
    cout << "}\n";
}

void printResults(const vector<ScanResult>& results, const string& target, double duration, bool verbose) {

    cout << "\nScanning " << target << "\n";
    cout << "-----------------------------------------------------------------------\n";

    if (verbose) {
        cout << left << setw(16) << "PORT"
                     << setw(16) << "STATE"
                     << setw(16) << "SERVICE"
                     << "BANNER" << "\n";
    } else {
        cout << left << setw(16) << "PORT"
                     << setw(16) << "STATE"
                     << "SERVICE" << "\n";
    }

    cout << "-----------------------------------------------------------------------\n";

    for (const auto& r : results) {
        if (verbose) {
            if (r.state != PortState::OPEN) continue;
        } else {
            if (r.state != PortState::OPEN && r.service == "unknown") continue;
        }

        string stateStr;
        string color;

        switch (r.state) {
            case PortState::OPEN:
                stateStr = "OPEN";
                color = GREEN;
                break;
            case PortState::CLOSED:
                stateStr = "CLOSED";
                color = RED;
                break;
            case PortState::FILTERED:
                stateStr = "FILTERED";
                color = YELLOW;
                break;
        }

        string portStr = to_string(r.port) + "/tcp";
        int statePadding  = 16 - stateStr.length();
        int servicePadding = 16 - r.service.length();

        if (verbose) {
            cout << left << setw(16) << portStr
                 << color << stateStr << RESET
                 << string(statePadding, ' ')
                 << r.service << string(servicePadding, ' ')
                 << r.banner << "\n";
        } else {
            cout << left << setw(16) << portStr
                 << color << stateStr << RESET
                 << string(statePadding, ' ')
                 << r.service << "\n";
        }
    }

    // check if anything was printed
    bool anyPrinted = false;
    for (const auto& r : results) {
        if (verbose) {
            if (r.state == PortState::OPEN) { anyPrinted = true; break; }
        } else {
            if (r.state == PortState::OPEN || r.service != "unknown") { anyPrinted = true; break; }
        }
    }

    if (!anyPrinted) {
        cout << "  No open ports found in range.\n";
        cout << "  All ports are closed or filtered.\n";
    }

    cout << "-----------------------------------------------------------------------\n";

    int open = 0, closed = 0, filtered = 0;
    for (const auto& r : results) {
        if (r.state == PortState::OPEN)     open++;
        if (r.state == PortState::CLOSED)   closed++;
        if (r.state == PortState::FILTERED) filtered++;
    }

    cout << "Open: "     << GREEN  << open     << RESET << "  "
         << "Closed: "   << RED    << closed   << RESET << "  "
         << "Filtered: " << YELLOW << filtered << RESET << "\n"
         << "Duration: " << duration << "s\n\n";
}

bool parseArgs(int argc, char* argv[], string& target, int& startPort, int& endPort, int& numThreads, bool& verbose, bool& json, int& topPorts, string& outputFile) {
    if (argc < 3) {
        cout << "Usage: ./scanner <target> -p <start>-<end> [-t threads] [-v] [--json] [--top-ports N]\n";
        cout << "Example: ./scanner 192.168.1.50 -p 1-1024 -t 50 -v\n";
        cout << "Example: ./scanner 192.168.1.50 --top-ports 20\n";
        return false;
    }

    target = argv[1];
    numThreads = 50;
    
    verbose = false;
    json = false;
    topPorts = 0;
    outputFile = "";

    for (int i = 2; i < argc; i++) {
        string arg = argv[i];

        if (arg == "-p" && i + 1 < argc) {
            string range = argv[++i];
            size_t dash = range.find('-');
            if (dash == string::npos) {
                cout << "Invalid port range. Use format: 1-1024\n";
                return false;
            }
            startPort = stoi(range.substr(0, dash));
            endPort   = stoi(range.substr(dash + 1));
        }

        if (arg == "-t" && i + 1 < argc) {
            numThreads = stoi(argv[++i]);
        }

        if (arg == "-v") {
            verbose = true;
        }

        if (arg == "--json") {
            json = true;
        }

        if (arg == "--top-ports" && i + 1 < argc) {
            topPorts = stoi(argv[++i]);
        }

         if (arg == "-oN" && i + 1 < argc) {
            outputFile = argv[++i];
        }
    }

    if (topPorts == 0 && (startPort < 1 || endPort > 65535 || startPort > endPort)) {
        cout << "Invalid port range.\n";
        return false;
    }

    return true;
}
int main(int argc, char* argv[]) {
    string target;
    int startPort, endPort, numThreads;
    bool verbose, json;
    int topPorts;
    string outputFile;

    if (!parseArgs(argc, argv, target, startPort, endPort, numThreads, verbose, json, topPorts, outputFile)) {
        return 1;
    }

    

    auto start = chrono::high_resolution_clock::now();

    vector<ScanResult> results;
    if (topPorts > 0) {
        vector<int> ports = getTopPorts(topPorts);
        cout << "Starting scan on " << target
             << "  top " << topPorts << " ports"
             << "  threads " << numThreads << "\n";
        results = For_TargPorts(target, ports, numThreads, verbose);
    } else {
        cout << "Starting scan on " << target
             << "  ports " << startPort << "-" << endPort
             << "  threads " << numThreads << "\n";
        results = scanRange(target, startPort, endPort, numThreads, verbose);
    }

    auto end = chrono::high_resolution_clock::now();
    double duration = chrono::duration<double>(end - start).count();

    sort(results.begin(), results.end(), [](const ScanResult& a, const ScanResult& b) {
        return a.port < b.port;
    });

   if (!outputFile.empty()) {
        ofstream file(outputFile);
        if (!file.is_open()) {
            cout << "Error: could not open file " << outputFile << "\n";
            return 1;
        }
        streambuf* originalCout = cout.rdbuf(file.rdbuf());

        if (json) {
            printJSON(results, target, duration);
        } else {
            printResults(results, target, duration, verbose);
        }

        cout.rdbuf(originalCout);
        file.close();
        cout << "Output saved to " << outputFile << "\n";
    } else {
        if (json) {
            printJSON(results, target, duration);
        } else {
            printResults(results, target, duration, verbose);
        }
    }

    return 0;
}