// Ocean FiveM Scanner — Dear ImGui (DirectX 11) frontend.
// Consent-based anti-cheat screenshare tool.

#include "scanner.hpp"
#include "report.hpp"

#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>

#include <d3d11.h>
#include <windows.h>
#include <shellapi.h>
#include <tchar.h>

#include <atomic>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#pragma comment(lib, "d3d11")
#pragma comment(lib, "shell32")

// Reads the "pin" value out of an .ocean session JSON file.
static std::string PinFromSessionFile(const std::wstring& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    std::string s = ss.str();
    auto k = s.find("\"pin\"");
    if (k == std::string::npos) return {};
    auto q1 = s.find('"', s.find(':', k));
    if (q1 == std::string::npos) return {};
    auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    return s.substr(q1 + 1, q2 - q1 - 1);
}

// ---- D3D state -------------------------------------------------------
static ID3D11Device*           g_pd3dDevice = nullptr;
static ID3D11DeviceContext*    g_pd3dContext = nullptr;
static IDXGISwapChain*         g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRTV = nullptr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

// ---- Shared scan state ----------------------------------------------
struct AppState {
    char        code[16] = "";
    char        backendUrl[256] = "";
    std::atomic<bool>  running{ false };
    std::atomic<bool>  done{ false };
    std::atomic<float> progress{ 0.0f };
    std::mutex  mtx;
    std::string status = "Idle";
    std::string token;
    ScanResult  result;
    bool        hasResult = false;
};
static AppState g_app;

static void StartScan() {
    if (g_app.running.load()) return;
    g_app.running = true;
    g_app.done = false;
    g_app.progress = 0.0f;
    g_app.hasResult = false;
    {
        std::lock_guard<std::mutex> lk(g_app.mtx);
        g_app.status = "Starting...";
        g_app.token.clear();
    }
    std::string code = g_app.code;

    std::thread([code]() {
        ScanResult r = RunScan([](float p, const std::string& s) {
            g_app.progress = p;
            std::lock_guard<std::mutex> lk(g_app.mtx);
            g_app.status = s;
        });
        std::string tok = BuildToken(code, r);
        {
            std::lock_guard<std::mutex> lk(g_app.mtx);
            g_app.result = r;
            g_app.token = tok;
            g_app.hasResult = true;
            g_app.status = "Scan complete — verdict: " + r.verdict;
        }
        g_app.running = false;
        g_app.done = true;
    }).detach();
}

// ---- Theme -----------------------------------------------------------
static void ApplyTheme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 10.0f;
    s.FrameRounding = 8.0f;
    s.GrabRounding = 8.0f;
    s.ChildRounding = 10.0f;
    s.PopupRounding = 8.0f;
    s.ScrollbarRounding = 8.0f;
    s.FramePadding = ImVec2(10, 7);
    s.ItemSpacing = ImVec2(10, 10);
    s.WindowPadding = ImVec2(20, 20);
    s.WindowBorderSize = 0.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]        = ImVec4(0.039f, 0.039f, 0.039f, 1.0f);
    c[ImGuiCol_ChildBg]         = ImVec4(0.067f, 0.067f, 0.067f, 1.0f);
    c[ImGuiCol_PopupBg]         = ImVec4(0.067f, 0.067f, 0.067f, 1.0f);
    c[ImGuiCol_Text]            = ImVec4(0.898f, 0.898f, 0.898f, 1.0f);
    c[ImGuiCol_TextDisabled]    = ImVec4(0.45f, 0.45f, 0.45f, 1.0f);
    c[ImGuiCol_Border]          = ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
    c[ImGuiCol_FrameBg]         = ImVec4(0.086f, 0.086f, 0.086f, 1.0f);
    c[ImGuiCol_FrameBgHovered]  = ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
    c[ImGuiCol_FrameBgActive]   = ImVec4(0.15f, 0.15f, 0.15f, 1.0f);
    c[ImGuiCol_Button]          = ImVec4(0.145f, 0.388f, 0.921f, 1.0f);
    c[ImGuiCol_ButtonHovered]   = ImVec4(0.231f, 0.470f, 0.980f, 1.0f);
    c[ImGuiCol_ButtonActive]    = ImVec4(0.118f, 0.333f, 0.800f, 1.0f);
    c[ImGuiCol_Header]          = ImVec4(0.145f, 0.388f, 0.921f, 0.25f);
    c[ImGuiCol_HeaderHovered]   = ImVec4(0.145f, 0.388f, 0.921f, 0.40f);
    c[ImGuiCol_HeaderActive]    = ImVec4(0.145f, 0.388f, 0.921f, 0.55f);
    c[ImGuiCol_PlotHistogram]   = ImVec4(0.145f, 0.388f, 0.921f, 1.0f);
    c[ImGuiCol_TableHeaderBg]   = ImVec4(0.086f, 0.086f, 0.086f, 1.0f);
    c[ImGuiCol_TableBorderLight]= ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
    c[ImGuiCol_TableBorderStrong]=ImVec4(0.15f, 0.15f, 0.15f, 1.0f);
    c[ImGuiCol_ScrollbarBg]     = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_ScrollbarGrab]   = ImVec4(0.15f, 0.15f, 0.15f, 1.0f);
}

static ImVec4 SeverityColor(const std::string& sev) {
    if (sev == "Critical") return ImVec4(0.86f, 0.15f, 0.15f, 1.0f);
    if (sev == "High")     return ImVec4(0.95f, 0.45f, 0.20f, 1.0f);
    if (sev == "Medium")   return ImVec4(0.92f, 0.70f, 0.13f, 1.0f);
    return ImVec4(0.40f, 0.60f, 0.95f, 1.0f);
}

// ---- UI --------------------------------------------------------------
static void DrawUI() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##root", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    // Header
    ImGui::PushFont(nullptr);
    ImGui::TextColored(ImVec4(0.231f, 0.470f, 0.980f, 1.0f), "(*>  OCEAN");
    ImGui::SameLine();
    ImGui::TextDisabled("FiveM Anti-Cheat Scanner  ·  v1.0");
    ImGui::PopFont();
    ImGui::Separator();
    ImGui::Spacing();

    // Consent banner
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.09f, 0.04f, 1.0f));
    ImGui::BeginChild("consent", ImVec2(0, 70), true);
    ImGui::TextWrapped(
        "By entering a session code and starting a scan you consent to an "
        "anti-cheat inspection of running processes and game files. The result "
        "is shared with the server administrator. Usermode scanners cannot "
        "detect kernel/DMA/external cheats.");
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::Spacing();

    // Session code + actions
    ImGui::Text("Session Code");
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##code", "e.g. F1T5F8C0", g_app.code,
        IM_ARRAYSIZE(g_app.code), ImGuiInputTextFlags_CharsUppercase);
    ImGui::SameLine();

    bool canScan = !g_app.running.load() && g_app.code[0] != '\0';
    if (!canScan) ImGui::BeginDisabled();
    if (ImGui::Button(g_app.running.load() ? "Scanning..." : "Start Scan",
                      ImVec2(150, 0)))
        StartScan();
    if (!canScan) ImGui::EndDisabled();

    ImGui::Spacing();

    // Progress
    std::string status;
    { std::lock_guard<std::mutex> lk(g_app.mtx); status = g_app.status; }
    ImGui::ProgressBar(g_app.progress.load(), ImVec2(-1, 6), "");
    ImGui::TextDisabled("%s", status.c_str());
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Results
    std::lock_guard<std::mutex> lk(g_app.mtx);
    if (g_app.hasResult) {
        const ScanResult& r = g_app.result;
        ImVec4 vc = r.verdict == "Cheating" ? ImVec4(0.86f, 0.15f, 0.15f, 1)
                  : r.verdict == "Suspicious" ? ImVec4(0.92f, 0.70f, 0.13f, 1)
                  : ImVec4(0.13f, 0.77f, 0.37f, 1);
        ImGui::Text("Verdict:");
        ImGui::SameLine();
        ImGui::TextColored(vc, "%s", r.verdict.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("  |  %s  ·  %s  ·  %d processes  ·  %d modules%s",
            r.host.c_str(), r.os.c_str(), r.processCount, r.moduleCount,
            r.fivemRunning ? "  ·  FiveM running" : "  ·  FiveM NOT running");

        ImGui::Spacing();
        if (ImGui::BeginTable("det", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY, ImVec2(0, 280))) {
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 90);
            ImGui::TableSetupColumn("Detection", ImGuiTableColumnFlags_WidthFixed, 200);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 130);
            ImGui::TableSetupColumn("Evidence");
            ImGui::TableHeadersRow();
            for (const auto& d : r.detections) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(SeverityColor(d.severity), "%s", d.severity.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(d.name.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%s", d.type.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextWrapped("%s", d.detail.c_str());
            }
            if (r.detections.empty()) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(ImVec4(0.13f, 0.77f, 0.37f, 1), "OK");
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted("No indicators found");
            }
            ImGui::EndTable();
        }

        ImGui::Spacing();
        ImGui::Text("Result token  (paste into the website: Pins -> Import Result)");
        ImGui::InputTextMultiline("##tok",
            (char*)g_app.token.c_str(), g_app.token.size() + 1,
            ImVec2(-1, 70), ImGuiInputTextFlags_ReadOnly);
        if (ImGui::Button("Copy Token", ImVec2(140, 0)))
            ImGui::SetClipboardText(g_app.token.c_str());

        // Optional backend upload
        ImGui::SameLine(0, 30);
        ImGui::SetNextItemWidth(280);
        ImGui::InputTextWithHint("##url", "optional backend URL (https://...)",
            g_app.backendUrl, IM_ARRAYSIZE(g_app.backendUrl));
        ImGui::SameLine();
        if (ImGui::Button("Upload") && g_app.backendUrl[0]) {
            std::string err;
            int n = MultiByteToWideChar(CP_UTF8, 0, g_app.backendUrl, -1, nullptr, 0);
            std::wstring wurl(n, 0);
            MultiByteToWideChar(CP_UTF8, 0, g_app.backendUrl, -1, wurl.data(), n);
            bool ok = UploadJson(wurl, BuildJson(g_app.code, r), err);
            g_app.status = ok ? "Uploaded to backend" : ("Upload failed: " + err);
        }
    } else {
        ImGui::TextDisabled("No scan yet. Enter the code from the website and press Start Scan.");
    }

    ImGui::End();
}

// ---- D3D plumbing ----------------------------------------------------
static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL lvls[] = { D3D_FEATURE_LEVEL_11_0 };
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
            0, lvls, 1, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
            &g_pd3dDevice, &fl, &g_pd3dContext) != S_OK)
        return false;

    ID3D11Texture2D* back = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&back));
    g_pd3dDevice->CreateRenderTargetView(back, nullptr, &g_mainRTV);
    back->Release();
    return true;
}

static void CleanupDeviceD3D() {
    if (g_mainRTV) { g_mainRTV->Release(); g_mainRTV = nullptr; }
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dContext) { g_pd3dContext->Release(); g_pd3dContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wp, lp)) return true;
    switch (msg) {
        case WM_SIZE:
            if (g_pd3dDevice && wp != SIZE_MINIMIZED && g_mainRTV) {
                g_mainRTV->Release(); g_mainRTV = nullptr;
                g_pSwapChain->ResizeBuffers(0, LOWORD(lp), HIWORD(lp),
                    DXGI_FORMAT_UNKNOWN, 0);
                ID3D11Texture2D* b = nullptr;
                g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&b));
                g_pd3dDevice->CreateRenderTargetView(b, nullptr, &g_mainRTV);
                b->Release();
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hWnd, msg, wp, lp);
}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    // If launched with an .ocean session file, prefill the pin so the
    // user only has to accept the consent prompt and scan.
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv && argc > 1) {
            std::string pin = PinFromSessionFile(argv[1]);
            if (!pin.empty()) {
                strncpy_s(g_app.code, pin.c_str(), sizeof(g_app.code) - 1);
            }
        }
        if (argv) LocalFree(argv);
    }

    WNDCLASSEXW wc{ sizeof(wc), CS_CLASSDC, WndProc, 0, 0, hInst,
        nullptr, nullptr, nullptr, nullptr, L"OceanScanner", nullptr };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Ocean FiveM Scanner",
        WS_OVERLAPPEDWINDOW, 100, 100, 980, 760,
        nullptr, nullptr, hInst, nullptr);

    if (!CreateDeviceD3D(hwnd)) { CleanupDeviceD3D(); return 1; }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ApplyTheme();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dContext);

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        DrawUI();
        ImGui::Render();

        const float clear[4] = { 0.039f, 0.039f, 0.039f, 1.0f };
        g_pd3dContext->OMSetRenderTargets(1, &g_mainRTV, nullptr);
        g_pd3dContext->ClearRenderTargetView(g_mainRTV, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInst);
    return 0;
}
