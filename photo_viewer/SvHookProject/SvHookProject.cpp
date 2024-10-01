#include <windows.h>
#include <detours.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>

// Global variable to track blocked actions
int blockedCount = 0;
int totalPolicies = 13;  // Number of active policies

// Function pointers for original functions
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
BOOL(WINAPI* TrueVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
LPVOID(WINAPI* TrueVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
VOID(WINAPI* TrueSleep)(DWORD) = Sleep;
BOOL(WINAPI* TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
HMODULE(WINAPI* TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
UINT(WINAPI* TrueGetSystemDirectoryW)(LPWSTR, UINT) = GetSystemDirectoryW;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
VOID(WINAPI* TrueExitProcess)(UINT) = ExitProcess;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;
BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"WriteFile called on handle: " << hFile << std::endl;
    if (nNumberOfBytesToWrite > 1048576) {  // Block writes larger than 1MB
        std::wcout << L"Blocked: Write size exceeds 1MB!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// Hooked WaitForSingleObject function
DWORD WINAPI HookedWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    std::wcout << L"Waiting on handle: " << hHandle << " for " << dwMilliseconds << " milliseconds" << std::endl;
    if (dwMilliseconds > 10000) {  // Block waiting more than 10 seconds
        std::wcout << L"Blocked: Wait time exceeds 10 seconds!" << std::endl;
        blockedCount++;
        return WAIT_FAILED;
    }
    return TrueWaitForSingleObject(hHandle, dwMilliseconds);
}

// Hooked VirtualProtect function
BOOL WINAPI HookedVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    std::wcout << L"Attempting to change memory protection." << std::endl;
    if (flNewProtect & PAGE_EXECUTE_READWRITE) {  // Block making memory executable
        std::wcout << L"Blocked: Making memory executable is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

// Hooked VirtualAlloc function
LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    std::wcout << L"Allocating memory of size: " << dwSize << std::endl;
    if (dwSize > 10485760) {  // Block large allocations over 10MB
        std::wcout << L"Blocked: Memory allocation exceeds 10MB!" << std::endl;
        blockedCount++;
        return NULL;
    }
    return TrueVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

// Hooked Sleep function
VOID WINAPI HookedSleep(DWORD dwMilliseconds) {
    std::wcout << L"Sleep called for " << dwMilliseconds << " milliseconds." << std::endl;
    if (dwMilliseconds > 5000) {  // Block sleep times over 5 seconds
        std::wcout << L"Blocked: Sleep time exceeds 5 seconds!" << std::endl;
        blockedCount++;
        return;
    }
    TrueSleep(dwMilliseconds);
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Reading from file handle: " << hFile << std::endl;
    // Placeholder logic to detect sensitive files
    if (nNumberOfBytesToRead > 100000) {  // Block reading from large files
        std::wcout << L"Blocked: Reading large file!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// Hooked LoadLibraryW function
HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
    std::wcout << L"Loading library: " << lpLibFileName << std::endl;
    if (wcsstr(lpLibFileName, L"restricted.dll")) {  // Block loading restricted libraries
        std::wcout << L"Blocked: Loading restricted library!" << std::endl;
        blockedCount++;
        return NULL;
    }
    return TrueLoadLibraryW(lpLibFileName);
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess() {
    std::wcout << L"GetCurrentProcess called." << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked ExitProcess function
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    std::wcout << L"Attempting to exit process with exit code: " << uExitCode << std::endl;
    if (uExitCode == 0) {  // Block exit with code 0
        std::wcout << L"Blocked: Exiting with code 0 is not allowed!" << std::endl;
        blockedCount++;
        return;
    }
    TrueExitProcess(uExitCode);
}

// Hooked DeleteFileW function
BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName) {
    std::wcout << L"Attempting to delete file: " << lpFileName << std::endl;
    if (wcsstr(lpFileName, L"critical.txt")) {  // Block deletion of critical files
        std::wcout << L"Blocked: Deleting critical file is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueDeleteFileW(lpFileName);
}

// Hooked CreateProcessW function
BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    std::wcout << L"Creating process: " << lpApplicationName << std::endl;
    if (dwCreationFlags & CREATE_SUSPENDED) {  // Block creation of suspended processes
        std::wcout << L"Blocked: Creating suspended processes is not allowed!" << std::endl;
        blockedCount++;
        return FALSE;
    }
    return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

// Hooked CreateFileW function
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wcout << L"Attempting to create or open file: " << lpFileName << std::endl;
    if (wcsstr(lpFileName, L"sensitive.txt")) {  // Block access to sensitive files
        std::wcout << L"Blocked: Access to sensitive file is not allowed!" << std::endl;
        blockedCount++;
        return INVALID_HANDLE_VALUE;
    }
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
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
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);
    std::cout << "[INFO] Executing shellcode..." << std::endl;
    __try {
        shellcode_func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cerr << "Error: Exception occurred during shellcode execution." << std::endl;
    }
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

int main() {
    // Timing analysis
    auto start = std::chrono::high_resolution_clock::now();

    // Start Detours transaction to hook the functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Attach hooks
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourAttach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourAttach(&(PVOID&)TrueVirtualAlloc, HookedVirtualAlloc);
    DetourAttach(&(PVOID&)TrueSleep, HookedSleep);
    DetourAttach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourAttach(&(PVOID&)TrueLoadLibraryW, HookedLoadLibraryW);
    //DetourAttach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);

    DetourTransactionCommit();

    // Example of loading and executing shellcode
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

    // Log execution time and blocked actions
    std::cout << "Execution Time: " << duration.count() << " seconds" << std::endl;
    std::cout << "Total Policies Applied: " << totalPolicies << std::endl;
    std::cout << "Total Actions Blocked: " << blockedCount << std::endl;

    // Detach hooks and restore original functions
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourDetach(&(PVOID&)TrueVirtualProtect, HookedVirtualProtect);
    DetourDetach(&(PVOID&)TrueVirtualAlloc, HookedVirtualAlloc);
    DetourDetach(&(PVOID&)TrueSleep, HookedSleep);
    DetourDetach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourDetach(&(PVOID&)TrueLoadLibraryW, HookedLoadLibraryW);
    //DetourDetach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);
    DetourDetach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourDetach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourDetach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);

    DetourTransactionCommit();

    return 0;
}
