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
// Corrected declaration of TrueCloseHandle
BOOL(WINAPI* TrueCloseHandle)(HANDLE) = CloseHandle;
HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
BOOL(WINAPI* TrueDeleteFileW)(LPCWSTR) = DeleteFileW;
BOOL(WINAPI* TrueReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
BOOL(WINAPI* TrueWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
VOID(WINAPI* TrueSleep)(DWORD) = Sleep;
DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
VOID(WINAPI* TrueExitProcess)(UINT) = ExitProcess;
HANDLE(WINAPI* TrueGetCurrentProcess)(void) = GetCurrentProcess;
UINT(WINAPI* TrueGetSystemDirectoryW)(LPWSTR, UINT) = GetSystemDirectoryW;

// Global variables for analysis
int blockedCount = 0;
int totalPolicies = 11;

// Hooked CloseHandle function
BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    std::wcout << L"Closing handle: " << hObject << std::endl;
    return TrueCloseHandle(hObject);  // Now the return types match
}


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

// Hooked CreateProcessW function
BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    std::wcout << L"Blocked: Creating processes is not allowed!" << std::endl;
    blockedCount++;
    return FALSE;
}

// Hooked DeleteFileW function
BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName) {
    std::wcout << L"Blocked: File deletion is not allowed!" << std::endl;
    blockedCount++;
    return FALSE;
}

// Hooked ReadFile function
BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Attempting to read from file handle: " << hFile << std::endl;

    // Policy: Limit read size to 1MB
    if (nNumberOfBytesToRead > 1048576) {
        std::wcout << L"Blocked: Read size exceeds 1MB!" << std::endl;
        blockedCount++;
        return FALSE;
    }

    return TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// Hooked WriteFile function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::wcout << L"Blocked: Writing to files is not allowed!" << std::endl;
    blockedCount++;
    return FALSE;
}

// Hooked Sleep function
VOID WINAPI HookedSleep(DWORD dwMilliseconds) {
    std::wcout << L"Modifying sleep time to 10ms" << std::endl;
    TrueSleep(10);
}

// Hooked WaitForSingleObject function
DWORD WINAPI HookedWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    std::wcout << L"WaitForSingleObject called on handle: " << hHandle << std::endl;
    return TrueWaitForSingleObject(hHandle, dwMilliseconds);
}

// Hooked ExitProcess function
VOID WINAPI HookedExitProcess(UINT uExitCode) {
    std::wcout << L"Blocked: Exiting the process is not allowed!" << std::endl;
    blockedCount++;
}

// Hooked GetCurrentProcess function
HANDLE WINAPI HookedGetCurrentProcess(void) {
    std::wcout << L"GetCurrentProcess called" << std::endl;
    return TrueGetCurrentProcess();
}

// Hooked GetSystemDirectoryW function
UINT WINAPI HookedGetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize) {
    std::wcout << L"GetSystemDirectoryW called with buffer size: " << uSize << std::endl;
    if (uSize < 1 || uSize > 1024) {
        std::wcout << L"Blocked: Invalid buffer size!" << std::endl;
        blockedCount++;
        return 0;
    }
    return TrueGetSystemDirectoryW(lpBuffer, uSize);
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
    // Allocate memory for the shellcode with execution permissions
    void* exec_mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation for shellcode failed!" << std::endl;
        return;
    }

    // Copy shellcode to the allocated memory
    memcpy(exec_mem, shellcode, size);

    // Flush the instruction cache to ensure the CPU sees the latest instructions
    FlushInstructionCache(GetCurrentProcess(), exec_mem, size);

    // Cast to function and execute the shellcode
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);
    std::cout << "[INFO] Executing shellcode..." << std::endl;

    __try {
        shellcode_func();  // Attempt to execute the shellcode
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cerr << "Error: Exception occurred while executing shellcode." << std::endl;
    }

    // Free the allocated memory after execution
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
    DetourAttach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);
    DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourAttach(&(PVOID&)TrueReadFile, HookedReadFile);
    //DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)TrueSleep, HookedSleep);
    DetourAttach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourAttach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourAttach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourAttach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);

    // Commit the transaction to activate the hooks
    DetourTransactionCommit();

    // Load and execute shellcodes
    std::vector<ShellcodeResult> results;
    size_t size;
    unsigned char* shellcode;
    std::vector<std::string> shellcodeList = {
        "C:/Users/TAQI SHAH/Desktop/hooks/shellcodes/windows_x64_messagebox.bin",
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
    DetourDetach(&(PVOID&)TrueCloseHandle, HookedCloseHandle);
    DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
    DetourDetach(&(PVOID&)TrueReadFile, HookedReadFile);
    DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)TrueSleep, HookedSleep);
    DetourDetach(&(PVOID&)TrueWaitForSingleObject, HookedWaitForSingleObject);
    DetourDetach(&(PVOID&)TrueExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)TrueGetCurrentProcess, HookedGetCurrentProcess);
    DetourDetach(&(PVOID&)TrueGetSystemDirectoryW, HookedGetSystemDirectoryW);
    DetourTransactionCommit();

    return 0;
}
