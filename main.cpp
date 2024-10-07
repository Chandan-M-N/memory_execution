#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <TlHelp32.h>
#include <filesystem>
#include <thread>

LPVOID MapFileToMemory(LPCSTR path) {
    if (!std::filesystem::exists(path))
        return nullptr;

    std::streampos size;
    std::ifstream file(path, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        size = file.tellg();
        char* mem = new char[size]();
        file.seekg(0, std::ios::beg);
        file.read(mem, size);
        file.close();
        return mem;
    }
    return nullptr;
}

int RunPE(LPPROCESS_INFORMATION processinfo, LPSTARTUPINFOW startinfo, LPVOID image, LPWSTR args) {
    WCHAR filepath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, filepath, sizeof(filepath) / sizeof(WCHAR))) // Use GetModuleFileNameW
        return -1;

    WCHAR buffer[MAX_PATH + 2048];
    ZeroMemory(buffer, sizeof(buffer));
    SIZE_T length = wcslen(filepath);
    memcpy(buffer, filepath, length * sizeof(WCHAR));
    buffer[length] = ' ';
    wcscat_s(buffer, sizeof(buffer) / sizeof(WCHAR), args); // Append args to buffer safely

    PIMAGE_DOS_HEADER dosheader = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    PIMAGE_NT_HEADERS ntheader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD64>(image) + dosheader->e_lfanew);
    if (ntheader->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    if (!CreateProcessW(NULL, buffer, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startinfo, processinfo)) // Call CreateProcessW
        return -1;

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(processinfo->hThread, &ctx)) {
        TerminateProcess(processinfo->hProcess, -4);
        return -1;
    }

    LPVOID imagebase = VirtualAllocEx(processinfo->hProcess, reinterpret_cast<LPVOID>(ntheader->OptionalHeader.ImageBase), ntheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (imagebase == NULL) {
        TerminateProcess(processinfo->hProcess, -5);
        return -1;
    }

    if (!WriteProcessMemory(processinfo->hProcess, imagebase, image, ntheader->OptionalHeader.SizeOfHeaders, NULL)) {
        TerminateProcess(processinfo->hProcess, -6);
        return -1;
    }

    for (SIZE_T i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionheader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD64>(image) + dosheader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * i);

        if (!WriteProcessMemory(processinfo->hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(imagebase) + sectionheader->VirtualAddress),
            reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(image) + sectionheader->PointerToRawData), sectionheader->SizeOfRawData, NULL)) {
            TerminateProcess(processinfo->hProcess, -7);
            return -1;
        }
    }

    if (!WriteProcessMemory(processinfo->hProcess, reinterpret_cast<LPVOID>(ctx.Rdx + sizeof(LPVOID) * 2), &imagebase, sizeof(LPVOID), NULL)) {
        TerminateProcess(processinfo->hProcess, -8);
        return -1;
    }

    ctx.Rcx = reinterpret_cast<DWORD64>(imagebase) + ntheader->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(processinfo->hThread, &ctx)) {
        TerminateProcess(processinfo->hProcess, -9);
        return -1;
    }

    if (!ResumeThread(processinfo->hThread)) {
        TerminateProcess(processinfo->hProcess, -10);
        return -1;
    }

    return 0;
}

int main() {
    PROCESS_INFORMATION shellcodeinfo;
    ZeroMemory(&shellcodeinfo, sizeof(shellcodeinfo));
    STARTUPINFOW startupinfo; // Changed to STARTUPINFOW
    ZeroMemory(&startupinfo, sizeof(startupinfo));
    startupinfo.cb = sizeof(STARTUPINFOW); // Set the size for the STARTUPINFO structure
    WCHAR args[] = L"";
    LPVOID shellcode = MapFileToMemory("C:\\Users\\LibraryUser\\Downloads\\64bit.exe");
    if (shellcode == nullptr) {
        std::cout << "Failed To Map File To Memory" << std::endl;
        return 1; // Return an integer value
    }

    std::thread thread([&] {
        if (!RunPE(&shellcodeinfo, &startupinfo, reinterpret_cast<LPVOID>(shellcode), args)) {
            WaitForSingleObject(shellcodeinfo.hProcess, INFINITE);
            DWORD returnvalue = 0;
            GetExitCodeProcess(shellcodeinfo.hProcess, &returnvalue);
            std::cout << "Exit Code: " << returnvalue << std::endl;
            CloseHandle(shellcodeinfo.hThread);
            CloseHandle(shellcodeinfo.hProcess);
        }
    });
    thread.join();
    delete[] shellcode; // Clean up allocated memory
    return 0; // Ensure the main function returns an int
}
