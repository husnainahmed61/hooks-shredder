#include <windows.h>
#include <detours.h>
#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <vector>

// Struct to store shellcode test results
struct ShellcodeResult {
    std::string shellcodeFile;
    bool blocked;
};

// Function pointers to original functions
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
BOOL(WINAPI* TrueVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
VOID(WINAPI* TrueExitProcess)(UINT) = ExitProcess;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;
BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
HANDLE(WINAPI* TrueCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR) = CreateFileMappingW;
BOOL(WINAPI* TrueCloseHandle)(HANDLE) = CloseHandle;

// Global variables
int blockedCount = 0;

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"WriteFile called on handle: " << hFile << std::endl;
    if (nNumberOfBytesToWrite > 1048576) {  // Restrict write size to 1MB
        std::wcout << L"Blocked: Write size exceeds 1MB!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// Hooked WaitForSingleObject function
DWORD WINAPI HookedWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    std::wcout << L"Waiting on handle: " << hHandle << " for " << dwMilliseconds << " milliseconds" << std::endl;
    if (dwMilliseconds > 1000) {  // Restrict waiting time to 1 second
        std::wcout << L"Blocked: Wait time exceeds 1 second!" << std::endl;
        blockedCount++;
        return WAIT_FAILED;
    }
    return TrueWaitForSingleObject(hHandle, dwMilliseconds);
}

// Hooked VirtualProtect function
BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    std::wcout << L"Attempting to change memory protection at address: " << lpAddress << std::endl;
    if (flNewProtect & PAGE_EXECUTE_READWRITE) {  // Prevent making memory executable
        std::wcout << L"Blocked: Making memory executable is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess() {
    std::wcout << L"GetCurrentProcess called." << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked ExitProcess function
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    std::wcout << L"Attempting to exit the process with exit code: " << uExitCode << std::endl;
    if (uExitCode == 0) {  // Block process exit with exit code 0
        std::wcout << L"Blocked: Exiting with code 0 is not allowed!" << std::endl;
        blockedCount++;
        return;
    }
    TrueExitProcess(uExitCode);
}

// Hooked DeleteFileW function
BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName) {
    std::wcout << L"Attempting to delete file: " << lpFileName << std::endl;
    if (wcsstr(lpFileName, L"critical_file.txt") != NULL) {  // Block deletion of critical files
        std::wcout << L"Blocked: Deleting critical file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueDeleteFileW(lpFileName);
}

// Hooked CreateProcessW function
BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    std::wcout << L"Attempting to create a process: " << lpCommandLine << std::endl;
    if (dwCreationFlags & CREATE_SUSPENDED) {  // Block suspended process creation
        std::wcout << L"Blocked: Creating suspended processes is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wcout << L"Attempting to open file: " << lpFileName << std::endl;
    if (wcsstr(lpFileName, L"restricted_file.txt") != NULL) {  // Block opening certain files
        std::wcout << L"Blocked: Access to restricted file is not allowed!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Hooked CreateFileMappingW function
HANDLE WINAPI HookedCreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
    std::wcout << L"Attempting to create a file mapping: " << lpName << std::endl;
    if (wcsstr(lpName, L"restricted_mapping") != NULL) {  // Block certain file mappings
        std::wcout << L"Blocked: Creating restricted file mapping is not allowed!" << std::endl;
        blockedCount++;
        return NULL;
    }
    return TrueCreateFileMappingW(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

// Hooked CloseHandle function
BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    std::wcout << L"Closing handle: " << hObject << std::endl;
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

    // Attach hooks for the functions
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourAttach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)TrueCreateFileMappingW, HookedCreateFileMappingW);
    DetourAttach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);

    // Commit the transaction to activate the hooks
    DetourTransactionCommit();

    // Load and execute shellcodes
    std::vector<ShellcodeResult> results;
    size_t size;
    unsigned char* shellcode;

    std::vector<std::string> shellcodeList = {
        // Add your shellcode paths here
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
        std::wcout << L"Testing shellcode: " << shellcodeFile.c_str() << std::endl;
        size_t size;
        unsigned char* shellcode = load_shellcode(shellcodeFile.c_str(), size);
        if (shellcode) {
            execute_shellcode(shellcode, size);
            delete[] shellcode;
        }
    }

    // End the timer for shellcode execution analysis
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    std::cout << "Execution Time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total Shellcodes Blocked: " << blockedCount << std::endl;

    // Detach all hooks and restore original functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourDetach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourDetach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourDetach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourDetach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID&)TrueCreateFileMappingW, HookedCreateFileMappingW);
    DetourDetach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);
    DetourTransactionCommit();

    return 0;
}
