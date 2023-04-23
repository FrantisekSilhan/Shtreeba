#include "FindProcessId.h"

#include <iostream>
#include <filesystem>
#include <sstream>

#include <Windows.h>
#include <shellapi.h>

#include "ShtreebaDLL.h"
#include "SVBEXE.h"

using _Start = bool(*)(ProcessInfo, const std::filesystem::path&);

static const inline int MessageBoxTimeoutW(HWND hWnd, const WCHAR* sText, const WCHAR* sCaption, UINT uType, DWORD dwMilliseconds)
{
    using _MessageBoxTimeoutW = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
    int iResult;
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32)
    {
        const auto MessageBoxTimeoutW{ reinterpret_cast<_MessageBoxTimeoutW>(GetProcAddress(hUser32, "MessageBoxTimeoutW")) };
        iResult = MessageBoxTimeoutW(hWnd, sText, sCaption, uType, 0, dwMilliseconds);
        FreeLibrary(hUser32);
    }
    else
        iResult = MessageBox(hWnd, sText, sCaption, uType);

    return iResult;
}

static const inline void adjustPrivileges()
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid.LowPart = 20; // 20 = SeDebugPrivilege
    tp.Privileges[0].Luid.HighPart = 0;

    if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, 0);
        CloseHandle(token);
    }
}

#include <fstream>
bool doesFileExist(const std::string& filename) {
    std::ifstream file(filename.c_str());
    return file.good();
}

#include <string>
#include <TlHelp32.h>

bool doesProcessExist(const std::wstring& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    Process32First(snapshot, &processInfo);
    do {
        if (processName == processInfo.szExeFile) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &processInfo));

    CloseHandle(snapshot);
    return false;
}

bool processContainsPattern(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return false;
    }

    DWORD processId = 0;
    do {
        std::wstring wideName = pe.szExeFile;
        std::string narrowName(wideName.begin(), wideName.end());
        if (narrowName == processName) {
            processId = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    if (processId == 0) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = NULL;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
            SIZE_T bytesRead;
            unsigned char* buffer = new unsigned char[mbi.RegionSize];
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
                for (unsigned char* p = buffer; p < buffer + bytesRead - 5; p++) {
                    if (p[0] == 0x1B && p[1] == 0xFF && p[2] == 0x23 && p[3] == 0xF8 && p[4] == 0xF6 && p[5] == 0x87) {
                        delete[] buffer;
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
            delete[] buffer;
        }
        address += mbi.RegionSize;
    }

    CloseHandle(hProcess);

    return false;
}

#include <commdlg.h>
#pragma comment(lib, "comdlg32.lib")

std::wstring openFileDialog() {
    OPENFILENAME ofn;
    wchar_t szFileName[MAX_PATH] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileName(&ofn) == TRUE) {
        return std::wstring(ofn.lpstrFile);
    }
    else {
        return std::wstring();
    }
}

bool createFile(const std::string& name, unsigned char* data, size_t size)
{
    std::ofstream file(name, std::ios::binary);
    if (file.is_open())
    {
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
        return true;
    }
    return false;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    const auto filePath{ openFileDialog() };
    if (filePath.empty()) {
        MessageBoxW(NULL, L"no file selected", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
    const auto processName{ L"csgo.exe" };
    const auto libraryName{ L"Shtreeba" };

    system("taskkill /F /T /IM steam.exe");
    Sleep(3000);

    if (!createFile("SVB.exe", SVB_exe, SVB_exe_len)) {
        MessageBoxW(NULL, L"SVB.exe creation failed", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
    if (!doesFileExist("SVB.exe")) {
        MessageBoxW(NULL, L"SVB.exe loading failed", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
    system("SVB.exe");
    Sleep(3000);
    system("start steam://rungameid/730");
    remove("SVB.exe");
    while (!processContainsPattern("csgo.exe")) {
        Sleep(1000);
    }
    Sleep(3000);

    if (!createFile("Shtreeba.dll", Shtreeba_dll, Shtreeba_dll_len)) {
        MessageBoxW(NULL, L"Shtreeba.dll creation failed", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    const auto hInst = LoadLibraryW(std::filesystem::absolute(std::filesystem::path(libraryName)).c_str());
    if (!hInst) {
        remove("Shtreeba.dll");
        std::wcout << "Shtreeba.dll loading failed\n";
        MessageBoxW(NULL, L"Shtreeba.dll loading failed", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }


    const auto Shtreeba = reinterpret_cast<_Start>(GetProcAddress(hInst, "Start"));
    if (!Shtreeba) {
        FreeLibrary(hInst);
        remove("Shtreeba.dll");
        std::wcout << "Failed to load function from library\n";
        MessageBoxW(NULL, L"Failed to load function from library", L"Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    try {
        adjustPrivileges();
        FindProcessId processList;
        const auto processInfo{ processList.getProcess(processName) };
        Shtreeba(processInfo, filePath);
    }
    catch (const std::exception& e) {
        FreeLibrary(hInst);
        remove("Shtreeba.dll");
        std::cerr << e.what() << '\n';
        MessageBoxA(NULL, e.what(), "Error", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }

    FreeLibrary(hInst);
    remove("Shtreeba.dll");
    return EXIT_SUCCESS;
}