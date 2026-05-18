#pragma once
#include <string>
#include <vector>
#include <functional>

struct Detection {
    std::string name;     // cheat / indicator name
    std::string type;     // category
    std::string severity; // Low | Medium | High | Critical
    std::string detail;   // evidence (process, path, module ...)
};

struct ScanResult {
    std::string host;            // machine name
    std::string os;              // OS version string
    std::string verdict;         // Clean | Suspicious | Cheating
    bool        fivemRunning = false;
    int         processCount = 0;
    int         moduleCount = 0;
    std::vector<Detection> detections;
};

// Runs all usermode checks. `progress` is called with 0..1 and a status line.
ScanResult RunScan(const std::function<void(float, const std::string&)>& progress);
