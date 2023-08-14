#include <iostream>
#include <chrono>
#include <thread>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcessByName(char* procName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    while (Process32Next(snapshot, &process)) {
        if (strcmp(process.szExeFile, procName)) {
            return process.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: DD-Injector.exe [Full path to DLL]\n"
                  << "Or drag and drop DLL file onto this executable\n";
        
        system("pause");
        return -1;
    }

    char* dllPath = argv[1];
    printf("DLL Path: %s\n", dllPath);

    DWORD procID = GetProcessByName("Minecraft.Windows.exe");
    if (procID == -1) {
        std::cout << "Failed to get process ID for Minecraft. Attempting to launch minecraft and try again\n";
        system("minecraft://");

        for (int i = 0; i < 5; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            procID = GetProcessByName("Minecraft.Windows.exe");
            if (procID != -1) break;
        } 
        
        std::cout << "Failed to get process ID. Ensure minecraft is running before using this program\n";
        system("pause");
        return -1;
    } printf("Minercaft Process ID: %i\n", procID);

    HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
    if (procHandle == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to get handle to process.";
        system("pause");
        return -1;
    } printf("Successfully got handle to Minecraft");

    LPVOID pathAddr = VirtualAllocEx(procHandle, nullptr, lstrlen(dllPath)+1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pathAddr == nullptr) {
        std::cout << "Failed to allocate process memory\n";
        system("pause");
        return -1;
    } printf("Memory allocated at: 0x%x", (unsigned int)(uintptr_t)pathAddr);

    bool memWriteResult = WriteProcessMemory(procHandle, pathAddr, dllPath, lstrlen(dllPath)+1, nullptr);
    if (!memWriteResult) {
        std::cout << "Failed to write dll path to process\n";
        system("pause");
        return -1;
    } printf("Dll path written successfully\n");

    HMODULE k32Handle = GetModuleHandleA("kernel32.dll");
    if (k32Handle <= 0) {
        std::cout << "Failed to get handle to \"kernel32.dll\"\n";
        system("pause");
        return -1;
    } printf("Found handle to \"kernel32.dll\"");

    FARPROC llFuncAddr = GetProcAddress(k32Handle, "LoadLibraryA");
    if (llFuncAddr == nullptr) {
        std::cout << "Failed to get address of \"LoadLibraryA\" function\n";
        system("pause");
        return -1;
    } printf("Found address of \"LoadLibraryA\"");

    HANDLE threadResult = CreateRemoteThread(procHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)llFuncAddr, pathAddr, 0, 0);
    if (threadResult == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create thread in remote process\n";
        system("pause");
        return -1;
    }

    std::cout << "DLL injected successfully!\n";

    system("pause");

    return 0;
}
