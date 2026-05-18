#pragma once
#include "scanner.hpp"
#include <string>

// Builds the JSON payload that the website understands.
std::string BuildJson(const std::string& sessionCode, const ScanResult& r);

// Base64( JSON ) — this is the token the admin pastes into the website.
std::string BuildToken(const std::string& sessionCode, const ScanResult& r);

// Optional: POST the JSON to an HTTP(S) endpoint (used only if a backend
// URL is configured). Returns true on 2xx. No-op friendly.
bool UploadJson(const std::wstring& url, const std::string& json, std::string& err);
