#include "main.h"
#include "memory_scan.h"
#include "process.h"
#include "font.h"
#include "rtti_window.h"
#include "aob_window.h"
#include "method_window.h"
#include "heap_window.h"

// Init global data
extern ProcessInfo GameProcessInfo = { nullptr };

// Data
static ID3D11Device* g_pd3dDevice = NULL;
static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
static IDXGISwapChain* g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);


static bool ScanProcess(DWORD procid) {
        if (!procid) {
                Log("procid is 0, no process selected");
                return false;
        }

        if (GameProcessInfo.process) {
                CloseHandle(GameProcessInfo.process);
                _aligned_free(GameProcessInfo.buffer);
                GameProcessInfo.rtti_map.clear();
        }

        Log("Scan Process ID: %u", procid);

        const auto proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procid);
        if (!proc_handle) {
                Log("Could not open process");
                return false;
        }

        const auto mb = GetProcessBlock(proc_handle);
        if (!mb.address) {
                Log("Could not get process block!");
                return false;
        }

        const auto buffer = _aligned_malloc((mb.size + 4095) & (~4095ULL), 4096);
        if (!buffer) {
                Log("Could not allocate memory for process buffer");
                return false;
        }

        GameProcessInfo.proc_id = procid;
        GameProcessInfo.process = proc_handle;
        GameProcessInfo.base_address = mb.address;
        GameProcessInfo.buffer_size = mb.size;
        GameProcessInfo.buffer = buffer;

        if (!RPM(mb.address, buffer, mb.size)) {
                Log("Could not read process memory");
                return false;
        }
        
        return true;
}

static void ScanGame() {
        static char target[64] = "Starfield";
        static bool specify_target = false;

        if (ImGui::Button("Scan Starfield")) {
                if (ImGui::IsKeyDown(ImGuiKey_LeftShift)) {
                        specify_target = true;
                }
                else {

                        char temp_name[64];
                        snprintf(temp_name, sizeof(temp_name), "%s.exe", target);

                        auto proc = GetProcessIdByExeName(temp_name);

                        if (!proc) {
                                proc = GetProcessIdByWindowTitle(L"Starfield");
                        }

                        // the operations below must be performed in this exact order
                        // each operation builds more info about the exe and is used by the next operation
                        if (ScanProcess(proc)) {
                                perform_exe_section_analysis();
                                perform_exe_version_analysis();
                                turbo_vtable_algorithm();

                                if (!ImGui::IsKeyDown(ImGuiKey_LeftCtrl)) {
                                        scan_vtable();
                                }
                        }
                }
        }
        if (specify_target) {
                ImGui::InputText("Target", target, sizeof(target));
        }
}


// Main code
int WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
        // Create application window
        //ImGui_ImplWin32_EnableDpiAwareness();
        WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "ImGui Example", NULL };
        ::RegisterClassEx(&wc);
        HWND hwnd = ::CreateWindowA(wc.lpszClassName, "LiveINI Research Tool", WS_OVERLAPPEDWINDOW, 100, 100, 600, 800, NULL, NULL, wc.hInstance, NULL);

        // Initialize Direct3D
        if (!CreateDeviceD3D(hwnd))
        {
                CleanupDeviceD3D();
                ::UnregisterClass(wc.lpszClassName, wc.hInstance);
                return 1;
        }

        // Show the window
        ::ShowWindow(hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(hwnd);

        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;

        // Setup Dear ImGui style
        ImGui::StyleColorsDark();

        //setup fonts
        io.Fonts->AddFontFromMemoryCompressedTTF(FONT_buffer, FONT_size, 16.f);

        // Setup Platform/Renderer backends
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

        // Main loop
        bool done = false;
        while (!done)
        {
                MSG msg;
                while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
                {
                        ::TranslateMessage(&msg);
                        ::DispatchMessage(&msg);
                        if (msg.message == WM_QUIT)
                                done = true;
                }
                if (done)
                        break;

                // Start the Dear ImGui frame
                ImGui_ImplDX11_NewFrame();
                ImGui_ImplWin32_NewFrame();
                ImGui::NewFrame();

                RECT r;
                GetClientRect(hwnd, &r);

                ImVec2 pos = { 0.f, 0.f };
                ImVec2 size = { (float)(r.right - r.left), (float)(r.bottom - r.top) };
                ImGui::SetNextWindowBgAlpha(0.1f);
                ImGui::SetNextWindowPos(pos);
                ImGui::SetNextWindowSize(size);

                const auto window_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus;
                if (ImGui::Begin("Window", nullptr, window_flags)) {
                        if (ImGui::BeginTabBar("main_tab_bar")) {
                                if (ImGui::BeginTabItem("Log")) {
                                        ScanGame();
                                        ImGui::SameLine();
                                        draw_log_window();
                                        ImGui::EndTabItem();
                                }
                                if (ImGui::BeginTabItem("Setting")) {
                                        scan_window_draw();
                                        ImGui::EndTabItem();
                                }
                                if (ImGui::BeginTabItem("RTTI")) {
                                        draw_rtti_window();
                                        ImGui::EndTabItem();
                                }
                                if (ImGui::BeginTabItem("AOB")) {
                                        draw_aob_window();
                                        ImGui::EndTabItem();
                                }
                                if (ImGui::BeginTabItem("Method")) {
                                        draw_method_window();
                                        ImGui::EndTabItem();
                                }
                                if (ImGui::BeginTabItem("Heap")) {
                                        draw_heap_window();
                                        ImGui::EndTabItem();
                                }
                                ImGui::EndTabBar();
                        }
                }
                ImGui::End();

                // Rendering
                ImGui::Render();
                const float clear_color_with_alpha[4] = { 0.f, 0.f, 0.f, 1.f };
                g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
                g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
                ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

                g_pSwapChain->Present(1, 0); // Present with vsync
                //g_pSwapChain->Present(0, 0); // Present without vsync
        }

        // Cleanup
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);

        return 0;
}

// Helper functions

bool CreateDeviceD3D(HWND hWnd)
{
        // Setup swap chain
        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hWnd;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
        D3D_FEATURE_LEVEL featureLevel;
        const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
        if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
                return false;

        CreateRenderTarget();
        return true;
}

void CleanupDeviceD3D()
{
        CleanupRenderTarget();
        if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
        if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
        if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

void CreateRenderTarget()
{
        ID3D11Texture2D* pBackBuffer;
        g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
        pBackBuffer->Release();
}

void CleanupRenderTarget()
{
        if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
                return true;

        switch (msg)
        {
        case WM_SIZE:
                if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
                {
                        CleanupRenderTarget();
                        g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                        CreateRenderTarget();
                }
                return 0;
        case WM_SYSCOMMAND:
                if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
                        return 0;
                break;
        case WM_DESTROY:
                ::PostQuitMessage(0);
                return 0;
        }
        return ::DefWindowProc(hWnd, msg, wParam, lParam);
}
