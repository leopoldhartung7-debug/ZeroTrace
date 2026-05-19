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

struct UsbDevice {
    std::string device;   // friendly name / model
    std::string serial;   // USBSTOR instance id
    std::string action;   // "Connected" | "Removed" | "Mounted"
    std::string time;     // last arrival / removal timestamp
    std::vector<std::string> contents; // top-level entries seen on the volume
};

struct DiscordServer {
    std::string name;     // guild / server name
    std::string id;       // guild id (if recoverable)
};

struct ScanResult {
    std::string host;            // machine name
    std::string os;              // OS version string
    std::string ip;              // public IP of the scanned machine
    std::string verdict;         // Clean | Suspicious | Cheating
    bool        fivemRunning = false;
    int         processCount = 0;
    int         moduleCount = 0;
    std::vector<Detection> detections;
    std::vector<UsbDevice> usb;  // recent USB / removable storage activity
    std::vector<DiscordServer> discordServers; // Discord guilds cached locally
};

// Runs all usermode checks. `progress` is called with 0..1 and a status line.
ScanResult RunScan(const std::function<void(float, const std::string&)>& progress);
