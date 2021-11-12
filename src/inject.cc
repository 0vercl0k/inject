// Axel '0vercl0k' Souchet - March 14 2020
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <tlhelp32.h>
#include <vector>


HANDLE OpenRemoteProcess(const uint32_t ProcessId) {
  const uint32_t ProcessRights =
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
      PROCESS_VM_WRITE | PROCESS_VM_READ;
  const HANDLE Process = OpenProcess(ProcessRights, false, ProcessId);

  if (Process == nullptr) {
    printf("Failed to open the remote process.\n");
    return INVALID_HANDLE_VALUE;
  }

  return Process;
}

PVOID AllocateMemInRemoteProcess(HANDLE hRemoteProcess,
                                 const std::filesystem::path &Path) {
  const std::string DllPath = Path.string();
  const size_t DllPathLen = DllPath.size() + 1;
  SIZE_T BytesWritten;

  const PVOID RemoteDllPath = VirtualAllocEx(hRemoteProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE);

  if (RemoteDllPath == nullptr) {
    printf("VirtualAllocEx failed.\n");
    goto Error;
  }

  if (!WriteProcessMemory(hRemoteProcess, RemoteDllPath, DllPath.c_str(),
                          DllPathLen,
                          &BytesWritten)) {
    VirtualFreeEx(hRemoteProcess, RemoteDllPath, 0, MEM_RELEASE);
    printf("WriteProcessMemory failed.\n");
    goto Error;
  }

  return RemoteDllPath;

Error:
  CloseHandle(hRemoteProcess);
  return nullptr;
}

HANDLE CreateThreadInRemoteProcess(HANDLE hRemoteProcess, PVOID RemoteDllPath) {
  PVOID LoadLibraryA;
  HANDLE Thread;
  DWORD Tid;

  const HMODULE Kernelbase = GetModuleHandleA("kernelbase");
  if (Kernelbase == nullptr) {
    printf("GetModuleHandleA failed.\n");
    goto Error;
  }

  LoadLibraryA = PVOID(GetProcAddress(Kernelbase, "LoadLibraryA"));
  if (LoadLibraryA == nullptr) {
    printf("GetProcAddress failed.\n");
    goto Error;
  }

  Thread = CreateRemoteThread(hRemoteProcess, nullptr, 0,
                                           LPTHREAD_START_ROUTINE(LoadLibraryA),
                                           RemoteDllPath, 0, &Tid);

  if (Thread == NULL) {
    printf("CreateRemoteThread failed.\n");
    goto Error;
  }

  printf("Thread with ID %d has been created.\n", Tid);

  return Thread;

Error:
  VirtualFreeEx(hRemoteProcess, RemoteDllPath, 0, MEM_RELEASE);
  CloseHandle(hRemoteProcess);
  return INVALID_HANDLE_VALUE;
}

DWORD InjectDll(const uint32_t ProcessId, const std::filesystem::path &Path) {
  DWORD InjectResult = EXIT_FAILURE;

  HANDLE hRemoteProcess = OpenRemoteProcess(ProcessId);
  if (hRemoteProcess == INVALID_HANDLE_VALUE) {
    return InjectResult;
  }
  
  const PVOID RemoteDllPath = AllocateMemInRemoteProcess(hRemoteProcess, Path);
  if (RemoteDllPath == nullptr) {
    return InjectResult;
  }

  const HANDLE Thread = CreateThreadInRemoteProcess(hRemoteProcess, RemoteDllPath);
  if (Thread == INVALID_HANDLE_VALUE) {
    return InjectResult;
  }

  WaitForSingleObject(Thread, INFINITE);

  DWORD ExitCode = 0;
  GetExitCodeThread(Thread, &ExitCode);
  InjectResult = EXIT_SUCCESS;

  if (ExitCode == 0) {
    printf("/!\\ The thread failed to load the dll. ");
    InjectResult = EXIT_FAILURE;
  }

  CloseHandle(Thread);
  VirtualFreeEx(hRemoteProcess, RemoteDllPath, 0, MEM_RELEASE);
  CloseHandle(hRemoteProcess);
  return InjectResult;
}

bool Pid2Name(const char *ProcessName, uint32_t &Pid) {
  PROCESSENTRY32 Pe32;
  HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snap == INVALID_HANDLE_VALUE) {
    return false;
  }

  Pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(Snap, &Pe32)) {
    CloseHandle(Snap);
    return false;
  }

  bool FoundPid = false;
  do {
    const bool Match = _stricmp(Pe32.szExeFile, ProcessName) == 0;
    if (Match) {
      if (FoundPid) {
        printf("There are several instances of %s, pid %d will be used.\n",
               Pe32.szExeFile, Pid);
      } else {
        FoundPid = true;
        Pid = Pe32.th32ProcessID;
      }
    }
  } while (Process32Next(Snap, &Pe32));

  CloseHandle(Snap);
  return FoundPid;
}

int main(int Argc, const char *Argv[]) {
  if (Argc != 3) {
    printf("./injectdll <pid | process name> <dll path | dll dir path>\n");
    return EXIT_FAILURE;
  }

  uint32_t ProcessId = strtol(Argv[1], nullptr, 0);
  if (ProcessId == 0) {
    const bool Success = Pid2Name(Argv[1], ProcessId);
    if (!Success) {
      printf("Pid2Name failed, exiting.\n");
      return EXIT_FAILURE;
    }
  }

  std::vector<std::filesystem::path> Dlls;
  if (std::filesystem::is_directory(Argv[2])) {
    const std::filesystem::directory_iterator DirIt(Argv[2]);
    for (const auto &DirEntry : DirIt) {
      if (DirEntry.path().extension().string() == ".dll") {
        Dlls.emplace_back(DirEntry);
      }
    }
  } else {
    Dlls.emplace_back(Argv[2]);
  }

  for (const std::filesystem::path &Dll : Dlls) {
    const std::filesystem::path DllAbsolute = std::filesystem::absolute(Dll);
    const DWORD Succeed = InjectDll(ProcessId, DllAbsolute);
    if (Succeed == EXIT_FAILURE) {
      printf("Error while injecting %ls in %d\n", DllAbsolute.c_str(),
             ProcessId);
      return EXIT_FAILURE;
    }

    printf("Successfully injected %ls in %d\n", DllAbsolute.c_str(), ProcessId);
  }

  printf("Done!\n");
  return EXIT_SUCCESS;
}