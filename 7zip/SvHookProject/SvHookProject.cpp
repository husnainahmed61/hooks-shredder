#include <windows.h>
#include <detours.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>

// Define a structure to track the results
struct ShellcodeResult {
    std::string shellcodeName;
    bool blocked;
};

// Hooked function pointers (same as before)
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
BOOL(WINAPI* TrueCloseHandle)(HANDLE) = CloseHandle;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
UINT(WINAPI* TrueGetSystemDirectoryW)(LPWSTR, UINT) = GetSystemDirectoryW;
HMODULE(WINAPI* TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
BOOL(WINAPI* TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;

// Global variables for analysis
int blockedCount = 0;
int totalPolicies = 8;  // We have 8 policies (one for each function)

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    std::wcout << L"Attempting to open file: " << lpFileName << std::endl;

    // Policy: Allow only .txt files
    if (wcsstr(lpFileName, L".txt") == NULL) {
        std::wcout << L"Blocked: Only .txt files are allowed!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }

    // Policy: Block write access
    if ((dwDesiredAccess & GENERIC_WRITE) || (dwDesiredAccess & GENERIC_ALL)) {
        std::wcout << L"Blocked: Write access is not allowed!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }

    // Policy: Allow only opening existing files (block creation)
    if (dwCreationDisposition != OPEN_EXISTING) {
        std::wcout << L"Blocked: Only existing files can be opened!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }

    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Hooked CloseHandle function
BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    std::wcout << L"Closing handle: " << hObject << std::endl;
    return TrueCloseHandle(hObject);
}

// Hooked DeleteFileW function
BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName) {
    std::wcout << L"Attempting to delete file: " << lpFileName << std::endl;
    std::wcout << L"Blocked: File deletion is not allowed!" << std::endl;
    blockedCount++;
    return FALSE;
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess(void) {
    std::wcout << L"GetCurrentProcess called" << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked GetSystemDirectoryW function
UINT WINAPI HookedGetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize) {
    std::wcout << L"Retrieving system directory" << std::endl;
    return TrueGetSystemDirectoryW(lpBuffer, uSize);
}

// Hooked LoadLibraryW function
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
    std::wcout << L"Loading library: " << lpLibFileName << std::endl;
    if (wcsstr(lpLibFileName, L"version.dll") == NULL) {
        std::wcout << L"Blocked: Only version.dll is allowed to be loaded!" << std::endl;
        blockedCount++;
        return NULL;
    }
    return TrueLoadLibraryW(lpLibFileName);
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to read from file handle: " << hFile << std::endl;
    if (nNumberOfBytesToRead > 1048576) {
        std::wcout << L"Blocked: Read size exceeds 1 MB!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to write to file handle: " << hFile << std::endl;
    std::wcout << L"Blocked: Writing to files is not allowed!" << std::endl;
    blockedCount++;
    return FALSE;
}

// Function to load shellcode from a binary file
unsigned char* load_shellcode(const char* filename, size_t& size) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open shellcode file: " << filename << std::endl;
        return nullptr;
    }

    size = file.tellg();
    unsigned char* buffer = new unsigned char[size];
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer), size);
    file.close();

    return buffer;
}

// Function to execute shellcode
void execute_shellcode(unsigned char* shellcode, size_t size) {
    void* exec_mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation for shellcode failed!" << std::endl;
        return;
    }

    memcpy(exec_mem, shellcode, size);
    FlushInstructionCache(GetCurrentProcess(), exec_mem, size);

    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);
    std::cout << "[INFO] Executing shellcode..." << std::endl;

    __try {
        shellcode_func();  // Attempt to execute the shellcode
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        std::cerr << "Error: Exception occurred while executing shellcode. Exception code: " << std::hex << exceptionCode << std::endl;
    }


    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

int main() {
    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Begin Detours transaction to hook the functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attach hooks
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);
    DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);
    DetourAttach(&(PVOID&)TrueLoadLibraryW, HookedLoadLibraryW);
    DetourAttach(&(PVOID&)TrueReadFile, HookedReadFile);
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);

    DetourTransactionCommit();

    // Load and execute shellcodes (you will run this for multiple shellcodes)
    std::vector<ShellcodeResult> results;
    size_t size;
    unsigned char* shellcode;
    std::vector<std::string> shellcodeList = {
 "C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_http.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_https.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_winhttp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_reverse_winhttps.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_messagebox.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_http.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_https.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_winhttp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_meterpreter_reverse_winhttps.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_pingback_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_powershell_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_powershell_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_powershell_reverse_tcp_ssl.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_shell_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_http.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_https.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_winhttp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_vncinject_reverse_winhttps.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_custom_bind_tcp.bin",
        // Add more shellcode file paths here
    };

    for (const auto& shellcodeFile : shellcodeList) {
        std::wcout << L"Testing shellcode: " << shellcodeFile.c_str() << std::endl;
        shellcode = load_shellcode(shellcodeFile.c_str(), size);
        if (shellcode) {
            execute_shellcode(shellcode, size);
            results.push_back({ shellcodeFile, blockedCount > 0 });
            delete[] shellcode;
        }
    }

    // End timing
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    // Display results
    std::cout << "Execution Time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total Policies: " << totalPolicies << std::endl;
    std::cout << "Total Shellcodes Tested: " << shellcodeList.size() << std::endl;
    std::cout << "Shellcodes Blocked: " << blockedCount << std::endl;

    for (const auto& result : results) {
        std::cout << "Shellcode: " << result.shellcodeName << " - " << (result.blocked ? "Blocked" : "Allowed") << std::endl;
    }

    return 0;
}
