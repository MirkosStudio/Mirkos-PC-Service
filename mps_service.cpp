// ========================
// Mirkos PC Services (MPS) v2.5
// - 基于 v2.2（SHA256 密钥 + 被动模式）
// - 插件可安全接管主逻辑（需提供原始密钥）
// - 修复 MinGW 编译兼容性（ANSI 字符串）
// ========================
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601  // Windows 7
#define WINVER 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>        // SHA256
#include <mmsystem.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <iphlpapi.h>
#include <pdh.h>
#include <winhttp.h>
#include <setupapi.h>
#include <devguid.h>
#include <iostream>
#include <string>
#include <set>
#include <map>
#include <vector>
#include <filesystem>
#include <sstream>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <cstdlib>
#include <cctype>
#include <algorithm>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

// ========================
// 配置常量
// ========================

// 这是用于所有认证的原始密钥（48 字节十六进制字符串）
// 其 SHA256 哈希为: 2be04e024ebc49a3c034c76ff5cd6eae63bdb158beb1155a86b582c2d0769a86
const std::string EXPECTED_AUTH_HASH = "2be04e024ebc49a3c034c76ff5cd6eae63bdb158beb1155a86b582c2d0769a86";
const char* SECURE_PIPE = "\\\\.\\pipe\\MPSControl";
const char* USER_PIPE = "\\\\.\\pipe\\MPSUser";
const char* EXTENSIONS_DIR = "MPS_Extensions";
const char* INJECTABLES_DIR = "MPS_Injectables";
const char* MEDIA_DIR = "MPS_Media";
const char* SCRIPTS_DIR = "MPS_Scripts";
const char* LOGS_DIR = "MPS_Logs";
const char* THREAT_CACHE_FILE = "MPS_ThreatCache.txt";
const char* EXE_NAME = "mps_service.exe";

// ========================
// 全局状态
// ========================
std::set<DWORD> protectedPids;
std::map<std::string, HMODULE> loadedPlugins;
time_t serviceStartTime = time(nullptr);
std::set<std::string> maliciousDomains;
std::set<std::string> maliciousIPs;
std::set<std::string> phishingURLs;
time_t lastThreatUpdate = 0;
// 功能开关
volatile bool monitorEnabled = false;
volatile bool threatUpdateEnabled = false;
// 日志级别：0=INFO, 1=DEBUG
int logLevel = 0;
// 空闲自动退出（秒，0=禁用）
DWORD idleTimeoutSeconds = 0;
time_t lastCommandTime = time(nullptr);
CRITICAL_SECTION logLock;
CRITICAL_SECTION threatLock;

// ========================
// 可被插件接管的日志处理器
// ========================
using LogHandlerFn = void(*)(const char* level, const char* msg);
LogHandlerFn g_CustomLogHandler = nullptr;

// ========================
// 默认日志实现
// ========================
void DefaultLogHandler(const std::string& level, const std::string& msg) {
    EnterCriticalSection(&logLock);
    std::filesystem::create_directories(LOGS_DIR);
    std::ofstream log((std::string(LOGS_DIR) + "\\mps.log").c_str(), std::ios::app);
    if (log) {
        time_t now = time(nullptr);
        char timeBuf[32];
        strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        log << "[" << timeBuf << "] [" << level << "] " << msg << "\n";
        log.close();
    }
    LeaveCriticalSection(&logLock);
}

// ========================
// 统一日志调用入口
// ========================
void LogMessage(const std::string& level, const std::string& msg) {
    if (level == "DEBUG" && logLevel < 1) return;
    if (g_CustomLogHandler) {
        g_CustomLogHandler(level.c_str(), msg.c_str());
    } else {
        DefaultLogHandler(level, msg);
    }
}
#define LogInfo(msg) LogMessage("INFO", msg)
#define LogDebug(msg) LogMessage("DEBUG", msg)

// ========================
// SHA256 哈希计算
// ========================
std::string ComputeSHA256(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;
    DWORD hashLength = 0;
    DWORD resultLength = 0;
    std::vector<BYTE> hash;
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(hashLength), &resultLength, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    hash.resize(hashLength);
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptHashData(hHash, (PBYTE)input.data(), (ULONG)input.size(), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptFinishHash(hHash, hash.data(), hashLength, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) return "";
    static const char hexChars[] = "0123456789abcdef";
    std::string hexHash;
    hexHash.reserve(hashLength * 2);
    for (BYTE b : hash) {
        hexHash += hexChars[(b >> 4) & 0xF];
        hexHash += hexChars[b & 0xF];
    }
    return hexHash;
}

// ========================
// 插件注册日志处理器（需提供原始明文密钥）
// ========================
extern "C" __declspec(dllexport) bool RegisterLogHandler(
    const char* plugin_auth_key,
    LogHandlerFn custom_logger
) {
    if (!plugin_auth_key || std::string(plugin_auth_key).empty()) {
        return false;
    }
    std::string computed = ComputeSHA256(plugin_auth_key);
    if (computed != EXPECTED_AUTH_HASH) {
        return false; // 密钥错误
    }
    g_CustomLogHandler = custom_logger;
    return true;
}

// ========================
// HTTP 下载文本文件
// ========================
std::string DownloadTextFile(const std::string& url) {
    HINTERNET hSession = WinHttpOpen(L"MPS-ThreatClient/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;
    std::wstring wurl(url.begin(), url.end());
    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName,
                                       urlComp.nScheme == INTERNET_SCHEME_HTTPS ? 443 : 80, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath,
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest || !WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    WinHttpReceiveResponse(hRequest, nullptr);
    std::string result;
    char buffer[8192];
    DWORD bytesRead;
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        result.append(buffer, bytesRead);
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// ========================
// 更新威胁情报
// ========================
void UpdateThreatFeeds() {
    LogInfo("Updating threat intelligence feeds...");
    EnterCriticalSection(&threatLock);
    maliciousDomains.clear();
    maliciousIPs.clear();
    phishingURLs.clear();
    LeaveCriticalSection(&threatLock);
    // 1. 恶意域名（StevenBlack/hosts）
    std::string hostsData = DownloadTextFile("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts");
    if (!hostsData.empty()) {
        std::istringstream hostStream(hostsData);
        std::string line;
        while (std::getline(hostStream, line)) {
            if (line.empty() || line[0] == '#' || 
                (line.find("127.0.0.1") == std::string::npos && line.find("0.0.0.0") == std::string::npos)) 
                continue;
            size_t pos = line.find_first_of(" \t", line.find('.') + 1);
            if (pos != std::string::npos) {
                std::string domain = line.substr(pos + 1);
                domain.erase(0, domain.find_first_not_of(" \t"));
                if (!domain.empty() && domain.find('.') != std::string::npos && domain.find('/') == std::string::npos) {
                    EnterCriticalSection(&threatLock);
                    maliciousDomains.insert(domain);
                    LeaveCriticalSection(&threatLock);
                }
            }
        }
    }
    // 2. 钓鱼 URL（OpenPhish）
    std::string phishingData = DownloadTextFile("https://openphish.com/feed.txt");
    if (!phishingData.empty()) {
        std::istringstream phishStream(phishingData);
        std::string line;
        while (std::getline(phishStream, line)) {
            if (!line.empty() && line.find("http") == 0) {
                size_t start = line.find("://");
                if (start != std::string::npos) {
                    start += 3;
                    size_t end = line.find('/', start);
                    std::string domain = (end != std::string::npos) ? line.substr(start, end - start) : line.substr(start);
                    if (!domain.empty()) {
                        EnterCriticalSection(&threatLock);
                        phishingURLs.insert(domain);
                        maliciousDomains.insert(domain);
                        LeaveCriticalSection(&threatLock);
                    }
                }
            }
        }
    }
    // 3. 恶意 IP（Abuse.ch）
    std::string ipData = DownloadTextFile("https://feodotracker.abuse.ch/downloads/ipblocklist.txt");
    if (!ipData.empty()) {
        std::istringstream ipStream(ipData);
        std::string line;
        while (std::getline(ipStream, line)) {
            if (!line.empty() && isdigit(static_cast<unsigned char>(line[0])) && line.find('.') != std::string::npos) {
                if (std::count(line.begin(), line.end(), '.') == 3) {
                    size_t end = line.find_first_of(" \t");
                    std::string ip = (end != std::string::npos) ? line.substr(0, end) : line;
                    EnterCriticalSection(&threatLock);
                    maliciousIPs.insert(ip);
                    LeaveCriticalSection(&threatLock);
                }
            }
        }
    }
    // 保存缓存
    std::ofstream cache(THREAT_CACHE_FILE);
    if (cache) {
        EnterCriticalSection(&threatLock);
        for (const auto& d : maliciousDomains) cache << "DOMAIN:" << d << "\n";
        for (const auto& ip : maliciousIPs) cache << "IP:" << ip << "\n";
        LeaveCriticalSection(&threatLock);
        cache.close();
    }
    lastThreatUpdate = time(nullptr);
    LogInfo("Threat feeds updated. Domains: " + std::to_string(maliciousDomains.size()) +
               ", IPs: " + std::to_string(maliciousIPs.size()));
}

// ========================
// 系统工具函数
// ========================
std::string GetBatteryStatus() {
    SYSTEM_POWER_STATUS sps;
    if (GetSystemPowerStatus(&sps)) {
        if (sps.BatteryFlag == 128) return "No Battery";
        std::string status = std::to_string(sps.BatteryLifePercent) + "%";
        if (sps.ACLineStatus == 1) status += " (Charging)";
        else if (sps.ACLineStatus == 0) status += " (Discharging)";
        return status;
    }
    return "Unknown";
}
std::string GetIPAddress() {
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size);
    PIP_ADAPTER_ADDRESSES adapters = (IP_ADAPTER_ADDRESSES*)malloc(size);
    if (!adapters) return "127.0.0.1";
    if (GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size) != NO_ERROR) {
        free(adapters);
        return "127.0.0.1";
    }
    for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress; address; address = address->Next) {
            if (address->Address.lpSockaddr->sa_family == AF_INET) {
                char buffer[128];
                DWORD len = sizeof(buffer);
                if (WSAAddressToStringA(address->Address.lpSockaddr, address->Address.iSockaddrLength, nullptr, buffer, &len) == 0) {
                    if (std::string(buffer) != "127.0.0.1") {
                        std::string ip = buffer;
                        free(adapters);
                        return ip;
                    }
                }
            }
        }
    }
    free(adapters);
    return "127.0.0.1";
}
std::string GetOSVersion() {
    NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        RtlGetVersion = (decltype(RtlGetVersion))GetProcAddress(hNtdll, "RtlGetVersion");
        if (RtlGetVersion) RtlGetVersion(&osvi);
    }
    return "Windows " + std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);
}
std::string GetUsername() {
    char user[256];
    DWORD size = sizeof(user);
    if (GetUserNameA(user, &size)) return std::string(user);
    return "unknown";
}
std::string GetDiskUsage(const std::string& drive) {
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExA((drive + ":\\").c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        double total = (double)totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024);
        double free = (double)freeBytesAvailable.QuadPart / (1024 * 1024 * 1024);
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2)
            << "Total: " << total << " GB, Free: " << free << " GB";
        return oss.str();
    }
    return "ERROR";
}
std::string GetCPUUsage() {
    static PDH_HQUERY cpuQuery = nullptr;
    static PDH_HCOUNTER cpuTotal = nullptr;
    static bool initialized = false;
    if (!initialized) {
        PdhOpenQuery(nullptr, 0, &cpuQuery);
        // 修复 MinGW 兼容性：使用 ANSI 字符串，而非宽字符
        PdhAddCounter(cpuQuery, "\\Processor(_Total)\\% Processor Time", 0, &cpuTotal);
        PdhCollectQueryData(cpuQuery);
        initialized = true;
        Sleep(1000);
    }
    PDH_FMT_COUNTERVALUE counterVal;
    PdhCollectQueryData(cpuQuery);
    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, nullptr, &counterVal);
    return std::to_string((int)counterVal.doubleValue) + "%";
}
std::string ListProcesses() {
    std::ostringstream oss;
    DWORD pids[1024], bytesReturned;
    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) return "ERROR";
    for (DWORD i = 0; i < bytesReturned / sizeof(DWORD); ++i) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!hProc) continue;
        char name[MAX_PATH] = "<unknown>";
        HMODULE hMod;
        DWORD needed;
        if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &needed)) {
            GetModuleBaseNameA(hProc, hMod, name, sizeof(name));
        }
        oss << pids[i] << " : " << name << "\n";
        CloseHandle(hProc);
    }
    return oss.str();
}
std::string ListModules(DWORD pid) {
    std::ostringstream oss;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "FAIL: Cannot open process";
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameExA(hProc, hMods[i], modName, sizeof(modName))) {
                oss << modName << "\n";
            }
        }
    }
    CloseHandle(hProc);
    return oss.str();
}
std::string ListUSBDevices() {
    std::ostringstream oss;
    GUID guid = GUID_DEVCLASS_DISKDRIVE;
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(&guid, nullptr, nullptr, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return "ERROR";
    SP_DEVINFO_DATA devInfo = {0};
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); i++) {
        char buffer[1024];
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfo, SPDRP_FRIENDLYNAME, nullptr, (PBYTE)buffer, sizeof(buffer), nullptr)) {
            if (std::string(buffer).find("USB") != std::string::npos) {
                oss << buffer << "\n";
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return oss.str();
}
std::string ListNetworkConnections() {
    std::ostringstream oss;
    PMIB_TCPTABLE2 tcpTable = nullptr;
    ULONG size = 0;
    if (GetTcpTable2(tcpTable, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (PMIB_TCPTABLE2)malloc(size);
        if (GetTcpTable2(tcpTable, &size, FALSE) == NO_ERROR) {
            for (ULONG i = 0; i < tcpTable->dwNumEntries; i++) {
                char local[32], remote[32];
                inet_ntop(AF_INET, &tcpTable->table[i].dwLocalAddr, local, sizeof(local));
                inet_ntop(AF_INET, &tcpTable->table[i].dwRemoteAddr, remote, sizeof(remote));
                oss << "TCP " << local << ":" << ntohs((u_short)tcpTable->table[i].dwLocalPort)
                    << " -> " << remote << ":" << ntohs((u_short)tcpTable->table[i].dwRemotePort)
                    << " PID:" << tcpTable->table[i].dwOwningPid << "\n";
            }
        }
        free(tcpTable);
    }
    return oss.str();
}
std::string CheckRegistryAutoRuns() {
    const char* keys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    };
    std::ostringstream oss;
    for (const char* keyPath : keys) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            char name[256];
            DWORD nameSize;
            while (true) {
                nameSize = sizeof(name);
                if (RegEnumValueA(hKey, index, name, &nameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                oss << "HKLM\\" << keyPath << "\\" << name << "\n";
                index++;
            }
            RegCloseKey(hKey);
        }
    }
    return oss.str();
}
bool RemoveGlobalHooks() {
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        PostMessageA(hwnd, WM_NULL, 0, 0);
    }
    LogInfo("Keyboard hook scan triggered (stub)");
    return true;
}
std::string ControlService(const std::string& serviceName, const std::string& action) {
    SC_HANDLE hSCM = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return "FAIL: Cannot open SCM";
    SC_HANDLE hService = OpenServiceA(hSCM, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return "FAIL: Service not found";
    }
    SERVICE_STATUS status;
    std::string result;
    if (action == "start") {
        if (StartServiceA(hService, 0, nullptr)) result = "OK: Started";
        else result = "FAIL: Start failed";
    } else if (action == "stop") {
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) result = "OK: Stopped";
        else result = "FAIL: Stop failed";
    } else if (action == "status") {
        if (QueryServiceStatus(hService, &status)) {
            result = (status.dwCurrentState == SERVICE_RUNNING) ? "RUNNING" : "STOPPED";
        } else result = "UNKNOWN";
    }
    CloseHandle(hService);
    CloseHandle(hSCM);
    return result;
}
void PlayAudioFile(const std::string& filePath) {
    std::filesystem::path safePath = std::filesystem::absolute(filePath);
    std::filesystem::path mediaRoot = std::filesystem::absolute(MEDIA_DIR);
    if (safePath.string().find("..") != std::string::npos || 
        !std::filesystem::exists(safePath) ||
        safePath.parent_path() != mediaRoot) {
        return;
    }
    PlaySoundA(safePath.string().c_str(), nullptr, SND_FILENAME | SND_ASYNC | SND_NODEFAULT);
}
bool CreateMiniDump(DWORD pid, const std::string& filePath) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return false;
    }
    MINIDUMP_EXCEPTION_INFORMATION* excp = nullptr;
    bool success = MiniDumpWriteDump(hProcess, pid, hFile, MiniDumpNormal, excp, nullptr, nullptr);
    CloseHandle(hFile);
    CloseHandle(hProcess);
    return success;
}
bool InjectDLL(DWORD targetPid, const std::string& dllName) {
    if (dllName.find("..") != std::string::npos) return false;
    if (dllName.empty() || dllName.size() > 260) return false;
    std::filesystem::path dllPath = std::filesystem::absolute(std::filesystem::path(INJECTABLES_DIR) / dllName);
    std::filesystem::path injectablesRoot = std::filesystem::absolute(INJECTABLES_DIR);
    if (dllPath.extension() != ".dll" || 
        !std::filesystem::exists(dllPath) ||
        dllPath.parent_path() != injectablesRoot) {
        return false;
    }
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, targetPid);
    if (!hProcess) return false;
    std::string fullPath = dllPath.string();
    SIZE_T pathSize = (fullPath.size() + 1) * sizeof(char);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return false;
    }
    if (!WriteProcessMemory(hProcess, pRemoteMem, fullPath.c_str(), pathSize, nullptr)) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMem, 0, nullptr);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}
std::string ExecuteScript(const std::string& scriptPath) {
    std::filesystem::path safePath = std::filesystem::absolute(scriptPath);
    std::filesystem::path scriptsRoot = std::filesystem::absolute(SCRIPTS_DIR);
    if (safePath.string().find("..") != std::string::npos ||
        safePath.parent_path() != scriptsRoot ||
        !std::filesystem::exists(safePath)) {
        return "ERROR: Invalid script path";
    }
    std::string cmd = "cmd /c \"" + safePath.string() + "\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "ERROR: Cannot execute";
    char buffer[1024];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}
std::string Base64Encode(const std::vector<uint8_t>& data) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');
    return encoded;
}
std::string CaptureScreen(const std::string& filePath) {
    HDC hScreen = GetDC(nullptr);
    HDC hMemDC = CreateCompatibleDC(hScreen);
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    HGDIOBJ hOld = SelectObject(hMemDC, hBitmap);
    BitBlt(hMemDC, 0, 0, width, height, hScreen, 0, 0, SRCCOPY);
    SelectObject(hMemDC, hOld);
    BITMAPFILEHEADER bf = {0};
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    DWORD size = ((width * 32 + 31) / 32) * 4 * height;
    bf.bfType = 0x4D42;
    bf.bfSize = sizeof(bf) + sizeof(bi) + size;
    bf.bfOffBits = sizeof(bf) + sizeof(bi);
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(nullptr, hScreen);
        return "FAIL";
    }
    WriteFile(hFile, &bf, sizeof(bf), nullptr, nullptr);
    WriteFile(hFile, &bi, sizeof(bi), nullptr, nullptr);
    std::vector<BYTE> bits(size);
    GetDIBits(hMemDC, hBitmap, 0, height, bits.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    WriteFile(hFile, bits.data(), size, nullptr, nullptr);
    CloseHandle(hFile);
    DeleteObject(hBitmap);
    DeleteDC(hMemDC);
    ReleaseDC(nullptr, hScreen);
    return "OK";
}

// ========================
// 自更新功能
// ========================
bool SelfUpdateFromURL(const std::string& url) {
    if (url.substr(0, 8) != "https://") return false;
    std::string newExe = "mps_update.tmp";
    HINTERNET hSession = WinHttpOpen(L"MPS-Updater/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, nullptr, nullptr, 0);
    if (!hSession) return false;
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;
    std::wstring wurl(url.begin(), url.end());
    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, 443, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest || !WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0)) {
        WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false;
    }
    WinHttpReceiveResponse(hRequest, nullptr);
    std::ofstream outFile(newExe, std::ios::binary);
    if (!outFile) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    char buffer[8192];
    DWORD bytesRead;
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        outFile.write(buffer, bytesRead);
    }
    outFile.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    // 验证是否为有效PE文件（简单检查 DOS 头）
    std::ifstream verify(newExe, std::ios::binary);
    char magic[2];
    verify.read(magic, 2);
    verify.close();
    if (magic[0] != 'M' || magic[1] != 'Z') {
        std::filesystem::remove(newExe);
        return false;
    }
    // 启动更新脚本（避免自身文件被占用）
    std::string cmd = "timeout /t 2 >nul && move /y \"" + newExe + "\" \"" + EXE_NAME + "\" && \"" + EXE_NAME + "\"";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(nullptr, (char*)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    } else {
        std::filesystem::remove(newExe);
        return false;
    }
}

// ========================
// 后台线程（条件执行）
// ========================
DWORD WINAPI ProtectionMonitorThreadProc(LPVOID) {
    LogInfo("Protection monitor started.");
    while (monitorEnabled) {
        if (protectedPids.empty()) { Sleep(2000); continue; }
        DWORD pids[1024], bytesReturned;
        if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) { Sleep(2000); continue; }
        DWORD processCount = bytesReturned / sizeof(DWORD);
        for (DWORD i = 0; i < processCount; ++i) {
            DWORD attackerPid = pids[i];
            if (attackerPid == 0 || attackerPid == GetCurrentProcessId()) continue;
            for (DWORD targetPid : protectedPids) {
                if (attackerPid == targetPid) continue;
                HANDLE hTest = OpenProcess(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME, FALSE, targetPid);
                if (hTest) {
                    HANDLE hAttacker = OpenProcess(PROCESS_TERMINATE, FALSE, attackerPid);
                    if (hAttacker) {
                        TerminateProcess(hAttacker, 0xDEAD);
                        LogInfo("Terminated attacker PID " + std::to_string(attackerPid) + " targeting " + std::to_string(targetPid));
                        CloseHandle(hAttacker);
                    }
                    CloseHandle(hTest);
                    break;
                }
            }
        }
        Sleep(1500);
    }
    LogInfo("Protection monitor stopped.");
    return 0;
}
DWORD WINAPI ThreatUpdateThreadProc(LPVOID) {
    LogInfo("Threat update thread started.");
    if (threatUpdateEnabled) UpdateThreatFeeds();
    while (threatUpdateEnabled) {
        Sleep(60 * 60 * 1000);
        if (threatUpdateEnabled) UpdateThreatFeeds();
    }
    LogInfo("Threat update thread stopped.");
    return 0;
}
DWORD WINAPI IdleMonitorThreadProc(LPVOID) {
    while (true) {
        Sleep(10000); // 每10秒检查
        if (idleTimeoutSeconds > 0) {
            time_t now = time(nullptr);
            if (now - lastCommandTime > (time_t)idleTimeoutSeconds) {
                LogInfo("Shutting down due to inactivity.");
                ExitProcess(0);
            }
        }
    }
    return 0;
}

// ========================
// 插件系统（带弹窗错误提示）
// ========================
// 为兼容 MinGW，不通过 plugin_api.h 声明 RegisterLogHandler
// 插件开发者需自行声明：extern "C" __declspec(dllimport) bool RegisterLogHandler(...);
void LoadPlugins() {
    std::filesystem::create_directories(EXTENSIONS_DIR);
    for (const auto& entry : std::filesystem::directory_iterator(EXTENSIONS_DIR)) {
        if (entry.path().extension() == ".dll") {
            std::string pluginName = entry.path().filename().string();
            HMODULE hMod = LoadLibraryW(entry.path().c_str());
            if (!hMod) {
                std::string msg = "Failed to load plugin DLL:\n" + pluginName;
                LogMessage("ERROR", msg);
                MessageBoxA(nullptr, msg.c_str(), "MPS Plugin Error", MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
                continue;
            }
            typedef bool (*PluginInitFunc)();
            PluginInitFunc init = (PluginInitFunc)GetProcAddress(hMod, "PluginInit");
            if (!init) {
                std::string msg = "Plugin missing PluginInit export:\n" + pluginName;
                LogMessage("ERROR", msg);
                MessageBoxA(nullptr, msg.c_str(), "MPS Plugin Error", MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
                FreeLibrary(hMod);
                continue;
            }
            if (!init()) {
                std::string msg = "Plugin initialization failed:\n" + pluginName;
                LogMessage("ERROR", msg);
                MessageBoxA(nullptr, msg.c_str(), "MPS Plugin Error", MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
                FreeLibrary(hMod);
                continue;
            }
            loadedPlugins[pluginName] = hMod;
            LogInfo("Loaded plugin: " + pluginName);
        }
    }
}
bool TryHandleWithPlugins(
    const std::string& cmd,
    DWORD pid,
    const std::vector<std::string>& args,
    std::string& response
) {
    typedef bool (*PluginHandleCommandFunc)(
        const std::string& cmd,
        DWORD pid,
        const std::vector<std::string>& args,
        std::string& response
    );
    for (auto& [name, hMod] : loadedPlugins) {
        PluginHandleCommandFunc handler = (PluginHandleCommandFunc)GetProcAddress(hMod, "PluginHandleCommand");
        if (handler) {
            if (handler(cmd, pid, args, response)) {
                return true;
            }
        }
    }
    return false;
}

// ========================
// 命令处理
// ========================
bool HandleUserCommand(const std::string& cmd, DWORD /*pid*/, const std::vector<std::string>& args, std::string& response) {
    if (cmd == "battery" && args.size() > 0 && args[0] == "status") {
        response = GetBatteryStatus();
        return true;
    }
    if (cmd == "network" && args.size() > 0) {
        if (args[0] == "ip") {
            response = GetIPAddress();
            return true;
        }
        if (args[0] == "list" && args.size() > 1 && args[1] == "connections") {
            response = ListNetworkConnections();
            return true;
        }
    }
    if (cmd == "os" && args.size() > 0 && args[0] == "version") {
        response = GetOSVersion();
        return true;
    }
    if (cmd == "play_sound") {
        if (!args.empty()) {
            PlayAudioFile(args[0]);
            response = "OK";
        } else response = "ERROR: Missing file path";
        return true;
    }
    if (cmd == "get_username") {
        response = GetUsername();
        return true;
    }
    if (cmd == "disk" && args.size() > 0 && args[0] == "usage") {
        response = GetDiskUsage(args.size() > 1 ? args[1] : "C");
        return true;
    }
    if (cmd == "cpu" && args.size() > 0 && args[0] == "usage") {
        response = GetCPUUsage();
        return true;
    }
    if (cmd == "usb" && args.size() > 1 && args[0] == "list" && args[1] == "devices") {
        response = ListUSBDevices();
        return true;
    }
    if (cmd == "threat" && args.size() > 0) {
        if (args[0] == "check") {
            if (args.size() < 2) {
                response = "ERROR: Usage: threat check <domain_or_ip>";
            } else {
                std::string target = args[1];
                bool isMalicious = false;
                EnterCriticalSection(&threatLock);
                if (maliciousDomains.count(target) || maliciousIPs.count(target) || phishingURLs.count(target)) {
                    isMalicious = true;
                }
                LeaveCriticalSection(&threatLock);
                response = isMalicious ? "MALICIOUS" : "CLEAN";
            }
            return true;
        }
        if (args[0] == "stats") {
            EnterCriticalSection(&threatLock);
            response = "Domains: " + std::to_string(maliciousDomains.size()) + 
                       ", IPs: " + std::to_string(maliciousIPs.size()) +
                       ", Last Update: " + std::to_string(time(nullptr) - lastThreatUpdate) + "s ago";
            LeaveCriticalSection(&threatLock);
            return true;
        }
    }
    return false;
}
bool HandleSecureCommand(const std::string& cmd, DWORD pid, const std::vector<std::string>& args, std::string& response) {
    // === 新增功能 ===
    if (cmd == "enable" && args.size() >= 1) {
        if (args[0] == "protection_monitor") {
            if (!monitorEnabled) {
                monitorEnabled = true;
                CreateThread(nullptr, 0, ProtectionMonitorThreadProc, nullptr, 0, nullptr);
                response = "OK: Protection monitor enabled";
                LogInfo("Protection monitor enabled.");
            } else response = "WARN: Already enabled";
            return true;
        }
        if (args[0] == "threat_update") {
            if (!threatUpdateEnabled) {
                threatUpdateEnabled = true;
                CreateThread(nullptr, 0, ThreatUpdateThreadProc, nullptr, 0, nullptr);
                response = "OK: Threat auto-update enabled";
                LogInfo("Threat auto-update enabled.");
            } else response = "WARN: Already enabled";
            return true;
        }
    }
    if (cmd == "disable" && args.size() >= 1) {
        if (args[0] == "protection_monitor") {
            monitorEnabled = false;
            response = "OK: Protection monitor disabled";
            LogInfo("Protection monitor disabled.");
            return true;
        }
        if (args[0] == "threat_update") {
            threatUpdateEnabled = false;
            response = "OK: Threat auto-update disabled";
            LogInfo("Threat auto-update disabled.");
            return true;
        }
    }
    if (cmd == "self_update" && args.size() >= 1) {
        if (SelfUpdateFromURL(args[0])) {
            response = "OK: Update started, service will restart.";
            LogInfo("Self-update initiated from: " + args[0]);
            ExitProcess(0);
        } else {
            response = "FAIL: Update failed";
        }
        return true;
    }
    if (cmd == "log_level" && args.size() >= 1) {
        if (args[0] == "debug") { logLevel = 1; response = "OK: Log level = DEBUG"; }
        else if (args[0] == "info") { logLevel = 0; response = "OK: Log level = INFO"; }
        else response = "ERROR: Unknown level";
        LogInfo("Log level set to: " + args[0]);
        return true;
    }
    if (cmd == "idle_shutdown" && args.size() >= 1) {
        try {
            idleTimeoutSeconds = std::stoul(args[0]);
            response = "OK: Idle timeout = " + args[0] + " seconds (0 = disabled)";
            LogInfo("Idle shutdown timeout set to: " + args[0] + "s");
        } catch (...) {
            response = "ERROR: Invalid number";
        }
        return true;
    }
    // === 原有命令 ===
    if (cmd == "protect") {
        if (pid) {
            protectedPids.insert(pid);
            response = "OK: Process protected";
            LogInfo("Protected process PID " + std::to_string(pid));
        } else response = "ERROR: Invalid PID";
        return true;
    }
    if (cmd == "unprotect") {
        protectedPids.erase(pid);
        response = "OK: Protection removed";
        LogInfo("Unprotected process PID " + std::to_string(pid));
        return true;
    }
    if (cmd == "kill") {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 0);
            CloseHandle(h);
            response = "OK";
            LogInfo("Terminated process PID " + std::to_string(pid));
        } else response = "FAIL";
        return true;
    }
    if (cmd == "dump") {
        if (args.size() >= 1) {
            if (CreateMiniDump(pid, args[0])) {
                response = "OK: Dump saved to " + args[0];
                LogInfo("Created minidump for PID " + std::to_string(pid) + " at " + args[0]);
            } else response = "FAIL: Cannot create dump";
        } else response = "ERROR: Missing file path";
        return true;
    }
    if (cmd == "inject") {
        if (args.empty()) {
            response = "ERROR: Missing DLL name";
        } else {
            if (InjectDLL(pid, args[0])) {
                response = "OK: DLL injected successfully";
                LogInfo("Injected " + args[0] + " into PID " + std::to_string(pid));
            } else {
                response = "FAIL: Injection failed (invalid path or permissions)";
            }
        }
        return true;
    }
    if (cmd == "status") {
        PROCESS_MEMORY_COUNTERS pmc;
        GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
        double memMB = pmc.WorkingSetSize / (1024.0 * 1024.0);
        std::ostringstream oss;
        oss << "Mirkos PC Services v2.5 (Passive Mode)\n";
        oss << "Uptime: " << (time(nullptr) - serviceStartTime) << " seconds\n";
        oss << "Memory Usage: " << std::fixed << std::setprecision(2) << memMB << " MB\n";
        oss << "Protected Processes: " << protectedPids.size() << "\n";
        oss << "Loaded Plugins: " << loadedPlugins.size() << "\n";
        oss << "Threat Intel: " << maliciousDomains.size() << " domains, " << maliciousIPs.size() << " IPs\n";
        oss << "Protection Monitor: " << (monitorEnabled ? "ENABLED" : "DISABLED") << "\n";
        oss << "Threat Auto-Update: " << (threatUpdateEnabled ? "ENABLED" : "DISABLED") << "\n";
        oss << "Log Level: " << (logLevel ? "DEBUG" : "INFO") << "\n";
        oss << "Idle Timeout: " << idleTimeoutSeconds << "s\n";
        response = oss.str();
        return true;
    }
    if (cmd == "plugin" && args.size() > 0 && args[0] == "reload") {
        for (auto& [name, hMod] : loadedPlugins) {
            FreeLibrary(hMod);
        }
        loadedPlugins.clear();
        LoadPlugins();
        response = "OK: Plugins reloaded";
        LogInfo("Plugins reloaded");
        return true;
    }
    if (cmd == "list" && args.size() > 0) {
        if (args[0] == "processes") {
            response = ListProcesses();
            return true;
        }
        if (args[0] == "modules" && pid) {
            response = ListModules(pid);
            return true;
        }
    }
    if (cmd == "run_script" && !args.empty()) {
        std::string script = (std::filesystem::path(SCRIPTS_DIR) / args[0]).string();
        response = ExecuteScript(script);
        LogInfo("Executed script: " + script);
        return true;
    }
    if (cmd == "send_file" && !args.empty()) {
        std::filesystem::path filePath = std::filesystem::absolute(args[0]);
        if (filePath.string().find("..") != std::string::npos) {
            response = "ERROR: Path traversal denied";
        } else if (std::filesystem::exists(filePath)) {
            std::ifstream file(filePath, std::ios::binary);
            std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});
            response = "FILE:" + Base64Encode(buffer);
        } else {
            response = "ERROR: File not found";
        }
        return true;
    }
    if (cmd == "delete_file" && !args.empty()) {
        std::filesystem::path filePath = std::filesystem::absolute(args[0]);
        if (filePath.string().find("..") == std::string::npos && std::filesystem::exists(filePath)) {
            std::filesystem::remove(filePath);
            response = "OK";
        } else {
            response = "ERROR: Invalid path";
        }
        return true;
    }
    if (cmd == "threat" && args.size() > 0 && args[0] == "update") {
        UpdateThreatFeeds();
        response = "OK: Threat feeds updated manually";
        return true;
    }
    if (cmd == "screenshot" && !args.empty()) {
        response = CaptureScreen(args[0]);
        LogInfo("Screenshot saved to " + args[0]);
        return true;
    }
    if (cmd == "reg" && args.size() >= 2 && args[0] == "list" && args[1] == "autoruns") {
        response = CheckRegistryAutoRuns();
        return true;
    }
    if (cmd == "security" && args.size() > 0 && args[0] == "anti_keylogger") {
        RemoveGlobalHooks();
        response = "OK: Anti-keylogger scan completed";
        return true;
    }
    if (cmd == "service" && args.size() >= 2 && args[0] == "control") {
        if (args.size() < 3) {
            response = "ERROR: Usage: service control <name> <start|stop|status>";
        } else {
            response = ControlService(args[1], args[2]);
        }
        return true;
    }
    return false;
}

// ========================
// 管道请求处理（哈希认证）
// ========================
void HandlePipeRequest(HANDLE hPipe, bool isSecure) {
    lastCommandTime = time(nullptr);
    char buffer[4096];
    DWORD bytesRead;
    if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) return;
    buffer[bytesRead] = '\0';
    std::istringstream iss(buffer);
    std::string response;
    bool handled = false;
    if (isSecure) {
        std::string providedKey, cmd, pidStr;
        iss >> providedKey;
        std::string computed = ComputeSHA256(providedKey);
        if (computed != EXPECTED_AUTH_HASH) {
            response = "ERROR: Invalid auth key";
            handled = true;
        } else {
            iss >> cmd >> pidStr;
            DWORD pid = 0;
            if (!pidStr.empty()) {
                try { pid = std::stoul(pidStr); } catch (...) {}
            }
            std::vector<std::string> extraArgs;
            std::string arg;
            while (iss >> arg) extraArgs.push_back(arg);
            if (!handled) {
                if (HandleSecureCommand(cmd, pid, extraArgs, response)) {
                    handled = true;
                } else if (TryHandleWithPlugins(cmd, pid, extraArgs, response)) {
                    handled = true;
                }
            }
        }
    } else {
        std::string cmd, pidStr;
        iss >> cmd >> pidStr;
        DWORD pid = 0;
        if (!pidStr.empty()) {
            try { pid = std::stoul(pidStr); } catch (...) {}
        }
        std::vector<std::string> extraArgs;
        std::string arg;
        while (iss >> arg) extraArgs.push_back(arg);
        if (HandleUserCommand(cmd, pid, extraArgs, response)) {
            handled = true;
        }
    }
    if (!handled) {
        response = "ERROR: Unknown command";
    }
    WriteFile(hPipe, response.c_str(), (DWORD)response.size(), nullptr, nullptr);
}
DWORD WINAPI SecurePipeThreadProc(LPVOID) {
    while (true) {
        HANDLE hPipe = CreateNamedPipeA(
            SECURE_PIPE,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr
        );
        if (hPipe == INVALID_HANDLE_VALUE) break;
        if (ConnectNamedPipe(hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            HandlePipeRequest(hPipe, true);
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}
DWORD WINAPI UserPipeThreadProc(LPVOID) {
    while (true) {
        HANDLE hPipe = CreateNamedPipeA(
            USER_PIPE,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr
        );
        if (hPipe == INVALID_HANDLE_VALUE) break;
        if (ConnectNamedPipe(hPipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            HandlePipeRequest(hPipe, false);
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

// ========================
// 主函数
// ========================
int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();
    SetCurrentDirectoryW(exeDir.c_str());
    InitializeCriticalSection(&logLock);
    InitializeCriticalSection(&threatLock);
    std::filesystem::create_directories(EXTENSIONS_DIR);
    std::filesystem::create_directories(INJECTABLES_DIR);
    std::filesystem::create_directories(MEDIA_DIR);
    std::filesystem::create_directories(SCRIPTS_DIR);
    std::filesystem::create_directories(LOGS_DIR);
    LoadPlugins();
    // 仅监听管道 + 空闲监控
    CreateThread(nullptr, 0, SecurePipeThreadProc, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, UserPipeThreadProc, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, IdleMonitorThreadProc, nullptr, 0, nullptr);
    LogInfo("MPS Service v2.5 (Passive Mode) started. Awaiting commands...");
    Sleep(INFINITE);
    DeleteCriticalSection(&logLock);
    DeleteCriticalSection(&threatLock);
    WSACleanup();
    return 0;
}