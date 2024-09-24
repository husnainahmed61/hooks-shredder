#include <windows.h>
#include <detours.h>
#include <iostream>
#include <chrono>
#include <vector>
#include <fstream>

// Struct to store shellcode test results
struct ShellcodeResult {
    std::string shellcodeFile;
    bool blocked;
};

// Hooked function pointers (combining previous and new ones)
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
BOOL(WINAPI* TrueVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
BOOL(WINAPI* TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
HMODULE(WINAPI* TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
UINT(WINAPI* TrueGetSystemDirectoryW)(LPWSTR, UINT) = GetSystemDirectoryW;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
VOID(WINAPI* TrueExitProcess)(UINT) = ExitProcess;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;

// Global variables for analysis
int blockedCount = 0;
int totalPolicies = 12;  // Updated with new function policies

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wcout << L"Attempting to open file: " << lpFileName << std::endl;

    // Policy: Allow only .txt files
    if (wcsstr(lpFileName, L".txt") == NULL) {
        std::wcout << L"Blocked: Only .txt files are allowed!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }

    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to write to file handle: " << hFile << std::endl;

    // Policy: Block write operations larger than 1MB
    if (nNumberOfBytesToWrite > 1048576) {
        std::wcout << L"Blocked: Write size exceeds 1MB!" << std::endl;
        blockedCount++;
        return FALSE;
    }

    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// Hooked WaitForSingleObject function
DWORD WINAPI HookedWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    std::wcout << L"Waiting on handle: " << hHandle << " for " << dwMilliseconds << " milliseconds" << std::endl;

    // Policy: Block if wait time is greater than 100ms
    if (dwMilliseconds > 100) {
        std::wcout << L"Blocked: Wait time exceeds 100ms!" << std::endl;
        blockedCount++;
        return WAIT_FAILED;
    }

    return TrueWaitForSingleObject(hHandle, dwMilliseconds);
}

// Hooked VirtualProtect function
BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    std::wcout << L"Attempting to change memory protection at address: " << lpAddress << std::endl;

    // Policy: Block if trying to make memory executable (e.g., PAGE_EXECUTE_READWRITE)
    if (flNewProtect & PAGE_EXECUTE_READWRITE) {
        std::wcout << L"Blocked: Making memory executable is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }

    return TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to read from file handle: " << hFile << std::endl;

    // Policy: Block reading from certain files (placeholder logic used)
    if (false) {  // Replace `false` with actual condition for sensitive files
        std::wcout << L"Blocked: Reading from sensitive file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }

    return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// Hooked LoadLibraryW function
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
    std::wcout << L"Attempting to load library: " << lpLibFileName << std::endl;

    // Policy: Block loading certain libraries
    if (wcsstr(lpLibFileName, L"untrusted.dll") != NULL) {
        std::wcout << L"Blocked: Loading untrusted library is not allowed!" << std::endl;
        blockedCount++;
        return NULL;
    }

    return TrueLoadLibraryW(lpLibFileName);
}

// Hooked GetSystemDirectoryW function
UINT WINAPI HookedGetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize) {
    std::wcout << L"GetSystemDirectoryW called with buffer size: " << uSize << std::endl;

    // Policy: Block access to specific system directories
    if (wcscmp(lpBuffer, L"C:\\Windows\\System32") == 0) {
        std::wcout << L"Blocked: Access to System32 directory is not allowed!" << std::endl;
        blockedCount++;
        return 0;
    }

    return TrueGetSystemDirectoryW(lpBuffer, uSize);
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess() {
    std::wcout << L"GetCurrentProcess called." << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked ExitProcess function
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    std::wcout << L"Attempting to exit the process with exit code: " << uExitCode << std::endl;

    // Policy: Block process termination (placeholder condition used)
    if (false) {  // Replace `false` with actual condition to block process exit
        std::wcout << L"Blocked: Exiting the process is not allowed!" << std::endl;
        blockedCount++;
        return;
    }

    TrueExitProcess(uExitCode);
}

// Hooked DeleteFileW function
BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName) {
    std::wcout << L"Attempting to delete file: " << lpFileName << std::endl;

    // Policy: Block deleting critical files
    if (wcsstr(lpFileName, L"critical_file.txt") != NULL) {
        std::wcout << L"Blocked: Deleting critical file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }

    return TrueDeleteFileW(lpFileName);
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
        std::cerr << "Error: Exception occurred while executing shellcode." << std::endl;
    }

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

// Main hooking and testing logic
int main() {
    // Start the timer for shellcode execution analysis
    auto start = std::chrono::high_resolution_clock::now();

    // Begin Detours transaction to hook the functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attach hooks for all functions
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourAttach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourAttach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourAttach(&(PVOID&)TrueLoadLibraryW, HookedLoadLibraryW);
    DetourAttach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);

    // Commit the transaction to activate the hooks
    DetourTransactionCommit();

    // Load and execute shellcodes
    std::vector<ShellcodeResult> results;
    size_t size;
    unsigned char* shellcode;
    std::vector<std::string> shellcodeList = {
        "C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_messagebox.bin",
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

    // End the timer for shellcode execution analysis
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    // Display results
    std::cout << "Execution Time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total Policies Applied: " << totalPolicies << std::endl;
    std::cout << "Total Shellcodes Blocked: " << blockedCount << std::endl;

    // Detach all hooks and restore original functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourDetach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourDetach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourDetach(&(PVOID&)TrueLoadLibraryW, HookedLoadLibraryW);
    DetourDetach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);
    DetourDetach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourDetach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourTransactionCommit();

    return 0;
}
