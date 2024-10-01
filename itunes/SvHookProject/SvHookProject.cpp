#include <windows.h>
#include <detours.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>

// Global variable for blocked count and execution analysis
int blockedCount = 0;
int totalPolicies = 12; // Keeping track of number of active policies

// Struct to store shellcode test results
struct ShellcodeResult {
    std::string shellcodeFile;
    bool blocked;
};

// Function pointers to original functions
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
BOOL(WINAPI* TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
HMODULE(WINAPI* TrueLoadLibraryA)(LPCSTR) = LoadLibraryA;
UINT(WINAPI* TrueGetSystemDirectoryA)(LPSTR, UINT) = GetSystemDirectoryA;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
VOID(WINAPI* TrueExitProcess)(UINT) = ExitProcess;
BOOL(WINAPI* TrueDeleteFileA)(LPCSTR) = DeleteFileA;
BOOL(WINAPI* TrueCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
HANDLE(WINAPI* TrueCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
BOOL(WINAPI* TrueCloseHandle)(HANDLE) = CloseHandle;

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"WriteFile called on handle: " << hFile << std::endl;
    if (nNumberOfBytesToWrite > 1048576) {  // Block writes greater than 1MB
        std::wcout << L"Blocked: Write size exceeds 1MB!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// Hooked WaitForSingleObject function
DWORD WINAPI HookedWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    std::wcout << L"Waiting on handle: " << hHandle << " for " << dwMilliseconds << " milliseconds" << std::endl;
    if (dwMilliseconds > 5000) {  // Block wait times over 5 seconds
        std::wcout << L"Blocked: Wait time exceeds 5 seconds!" << std::endl;
        blockedCount++;
        return WAIT_FAILED;
    }
    return TrueWaitForSingleObject(hHandle, dwMilliseconds);
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to read from file handle: " << hFile << std::endl;
    if (nNumberOfBytesToRead > 100000) {  // Block reading of files with over 100KB
        std::wcout << L"Blocked: Reading large file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// Hooked LoadLibraryA function
HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
    std::wcout << L"Loading library: " << lpLibFileName << std::endl;
    if (strstr(lpLibFileName, "kernel32.dll")) {  // Block certain libraries
        std::wcout << L"Blocked: Loading kernel32.dll is not allowed!" << std::endl;
        blockedCount++;
        return NULL;
    }
    return TrueLoadLibraryA(lpLibFileName);
}

// Hooked GetSystemDirectoryA function
UINT WINAPI HookedGetSystemDirectoryA(LPSTR lpBuffer, UINT uSize) {
    std::wcout << L"GetSystemDirectoryA called." << std::endl;
    return TrueGetSystemDirectoryA(lpBuffer, uSize);
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess() {
    std::wcout << L"GetCurrentProcess called." << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked ExitProcess function
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    std::wcout << L"Attempting to exit the process with exit code: " << uExitCode << std::endl;
    if (uExitCode == 0) {  // Block exit if exit code is 0
        std::wcout << L"Blocked: Exiting with code 0 is not allowed!" << std::endl;
        blockedCount++;
        return;
    }
    TrueExitProcess(uExitCode);
}

// Hooked DeleteFileA function
BOOL WINAPI HookedDeleteFileA(LPCSTR lpFileName) {
    std::wcout << L"Attempting to delete file: " << lpFileName << std::endl;
    if (strstr(lpFileName, "critical.txt")) {  // Block deletion of critical files
        std::wcout << L"Blocked: Deleting critical file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueDeleteFileA(lpFileName);
}

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wcout << L"Attempting to open file: " << lpFileName << std::endl;
    if (wcsstr(lpFileName, L"restricted_file.txt")) {  // Block creation of restricted files
        std::wcout << L"Blocked: Access to restricted file is not allowed!" << std::endl;
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

// Shellcode loading function
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

// Shellcode execution function
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
        shellcode_func();  // Execute shellcode
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cerr << "Error: Exception occurred during shellcode execution." << std::endl;
    }

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

// Main hooking and testing logic
int main() {
    // Start the timer for analysis
    auto start = std::chrono::high_resolution_clock::now();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attach hooks
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourAttach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourAttach(&(PVOID&)TrueLoadLibraryA, HookedLoadLibraryA);
    DetourAttach(&(PVOID&)TrueGetSystemDirectoryA, HookedGetSystemDirectoryA);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourAttach(&(PVOID&)TrueDeleteFileA, HookedDeleteFileA);
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);

    DetourTransactionCommit();

    // Test shellcode execution
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
    };
    for (const auto& shellcodeFile : shellcodeList) {
        size_t size;
        unsigned char* shellcode = load_shellcode(shellcodeFile.c_str(), size);
        if (shellcode) {
            execute_shellcode(shellcode, size);
            delete[] shellcode;
        }
    }

    // End the timer for analysis
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    // Log execution time and blocked count
    std::cout << "Execution Time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total Policies Applied: " << totalPolicies << std::endl;
    std::cout << "Total Actions Blocked: " << blockedCount << std::endl;

    // Detach hooks and restore original functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourDetach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourDetach(&(PVOID&)TrueLoadLibraryA, HookedLoadLibraryA);
    DetourDetach(&(PVOID&)TrueGetSystemDirectoryA, HookedGetSystemDirectoryA);
    DetourDetach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourDetach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)TrueDeleteFileA, HookedDeleteFileA);
    DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);
    DetourTransactionCommit();

    return 0;
}
