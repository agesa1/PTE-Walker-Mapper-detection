#ifndef PTE_WALKER_H
#define PTE_WALKER_H

#include <ntddk.h>

// System information class
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

// System module structures
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// ZwQuerySystemInformation
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// PTE indeks hesaplama makroları
#define PML4_INDEX(va) (((ULONG64)(va) >> 39) & 0x1FF)
#define PDPT_INDEX(va) (((ULONG64)(va) >> 30) & 0x1FF)
#define PD_INDEX(va)   (((ULONG64)(va) >> 21) & 0x1FF)
#define PT_INDEX(va)   (((ULONG64)(va) >> 12) & 0x1FF)

// PTE yapısı (64-bit)
typedef union _PTE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 LargePage : 1;
        ULONG64 Global : 1;
        ULONG64 CopyOnWrite : 1;
        ULONG64 Prototype : 1;
        ULONG64 Reserved0 : 1;
        ULONG64 PageFrameNumber : 36;
        ULONG64 Reserved1 : 4;
        ULONG64 SoftwareWsIndex : 11;
        ULONG64 NoExecute : 1;
    };
} PTE, *PPTE;

// Type definitions
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

// Forward declarations for kernel functions
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
);

NTKERNELAPI VOID KeStackAttachProcess(
    _Inout_ PEPROCESS Process,
    _Out_ PRKAPC_STATE ApcState
);

NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ PRKAPC_STATE ApcState
);

// Fonksiyon prototipleri
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS WalkPageTable(PVOID VirtualAddress);
VOID LogToFile(PCWSTR Message);

#endif // PTE_WALKER_H
