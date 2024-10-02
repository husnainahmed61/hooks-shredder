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

// Hooked function pointers
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
HANDLE(WINAPI* TrueCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR) = CreateFileMappingW;
BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;
VOID(WINAPI* TrueExitProcess)(UINT) = ExitProcess;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
BOOL(WINAPI* TrueVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
BOOL(WINAPI* TrueCloseHandle)(HANDLE) = CloseHandle;

// Global variables for analysis
int blockedCount = 0;
int totalPolicies = 10;  // Update this with more policies

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to write to file handle: " << hFile << std::endl;
    // Block writes larger than 1MB
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
    // Block if wait time exceeds 100ms
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
    // Block if trying to make memory executable
    if (flNewProtect & PAGE_EXECUTE_READWRITE) {
        std::wcout << L"Blocked: Making memory executable is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}



// Hooked DeleteFileW function
BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName) {
    std::wcout << L"Attempting to delete file: " << lpFileName << std::endl;
    // Block deleting critical files (e.g., "critical.txt")
    if (wcsstr(lpFileName, L"critical_file.txt") != NULL) {
        std::wcout << L"Blocked: Deleting critical file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueDeleteFileW(lpFileName);
}

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wcout << L"Attempting to create or open file: " << lpFileName << std::endl;
    // Block specific files (e.g., "blocked_file.txt")
    if (wcsstr(lpFileName, L"blocked_file.txt") != NULL) {
        std::wcout << L"Blocked: File creation or access is not allowed for this file!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


// Hooked CreateProcessW function
BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    std::wcout << L"Attempting to create process: " << lpApplicationName << std::endl;
    // Block creation of specific processes (e.g., "dangerous_app.exe")
    if (wcsstr(lpApplicationName, L"dangerous_app.exe") != NULL) {
        std::wcout << L"Blocked: Creating process is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess() {
    std::wcout << L"GetCurrentProcess called." << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked ExitProcess function
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    std::wcout << L"Attempting to exit the process with exit code: " << uExitCode << std::endl;

    // Block exit if the exit code is 0 (example condition)
    if (uExitCode == 0) {
        std::wcout << L"Blocked: Exiting the process with exit code 0 is not allowed!" << std::endl;
        blockedCount++;
        return;  // Block the exit
    }

    TrueExitProcess(uExitCode);  // Allow exit otherwise
}

// Hooked CloseHandle function
BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    std::wcout << L"Attempting to close handle: " << hObject << std::endl;
    // Block handle closure in certain cases
    return TrueCloseHandle(hObject);
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
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourAttach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourAttach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);

    // Commit the transaction to activate the hooks
    DetourTransactionCommit();

    // Load and execute shellcodes
    std::vector<ShellcodeResult> results;
    size_t size;
    unsigned char* shellcode;
    std::vector<std::string> shellcodeList = {
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_http.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_https.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_winhttp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_reverse_winhttps.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_messagebox.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_http.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_https.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_winhttp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_meterpreter_reverse_winhttps.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_pingback_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_powershell_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_powershell_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_powershell_reverse_tcp_ssl.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_shell_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_bind_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_bind_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_bind_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_http.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_https.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_tcp_rc4.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_winhttp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_vncinject_reverse_winhttps.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_bind_ipv6_tcp.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_bind_ipv6_tcp_uuid.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_bind_named_pipe.bin",
"C:/Users/TAQI SHAH/Desktop/shredder/hooks-shredder/shellcodes/windows_x64_custom_bind_tcp.bin",
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
    DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourDetach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourDetach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourDetach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);
    DetourTransactionCommit();

    return 0;
}
