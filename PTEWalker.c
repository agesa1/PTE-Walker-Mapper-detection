#include <ntddk.h>
#include <ntstrsafe.h>
#include "PTEWalker.h"

PKTHREAD g_ScanThread = NULL;
KEVENT g_StopEvent;
BOOLEAN g_StopScanning = FALSE;
HANDLE g_LogFileHandle = NULL;
UNICODE_STRING g_LogFilePath;
PRTL_PROCESS_MODULES g_SystemModules = NULL;

VOID LogToFile(PCWSTR Message) {
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER byteOffset;
    WCHAR timestampBuffer[512];
    LARGE_INTEGER systemTime, localTime;
    TIME_FIELDS timeFields;
    
    if (g_LogFileHandle == NULL) {
        return;
    }
    
    __try {
        KeQuerySystemTime(&systemTime);
        ExSystemTimeToLocalTime(&systemTime, &localTime);
        RtlTimeToTimeFields(&localTime, &timeFields);
        
        RtlStringCbPrintfW(timestampBuffer, sizeof(timestampBuffer),
            L"%02d:%02d:%02d.%03d %s\r\n",
            timeFields.Hour, timeFields.Minute, timeFields.Second,
            timeFields.Milliseconds, Message);
        
        byteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;
        byteOffset.HighPart = -1;
        
        status = ZwWriteFile(
            g_LogFileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            timestampBuffer,
            (ULONG)wcslen(timestampBuffer) * sizeof(WCHAR),
            &byteOffset,
            NULL
        );
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }
}

NTSTATUS InitializeLogFile(VOID) {
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    
    RtlInitUnicodeString(&g_LogFilePath, L"\\??\\C:\\pte_walker_log.txt");
    
    InitializeObjectAttributes(
        &objAttr,
        &g_LogFilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    
    status = ZwCreateFile(
        &g_LogFileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    
    if (NT_SUCCESS(status)) {
        LogToFile(L"Driver initialized");
    }
    
    return status;
}

VOID CloseLogFile(VOID) {
    if (g_LogFileHandle != NULL) {
        LogToFile(L"Driver unloading");
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
    }
}

NTSTATUS CacheSystemModules(VOID) {
    NTSTATUS status;
    ULONG bufferSize = 0;
    WCHAR logBuffer[256];
    
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return STATUS_UNSUCCESSFUL;
    }
    
    g_SystemModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, 
        bufferSize, 
        'domS'
    );
    
    if (g_SystemModules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        g_SystemModules,
        bufferSize,
        &bufferSize
    );
    
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_SystemModules, 'domS');
        g_SystemModules = NULL;
        return status;
    }
    
    RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
        L"Modules cached: %d", g_SystemModules->NumberOfModules);
    LogToFile(logBuffer);
    
    return STATUS_SUCCESS;
}

VOID FreeSystemModules(VOID) {
    if (g_SystemModules != NULL) {
        ExFreePoolWithTag(g_SystemModules, 'domS');
        g_SystemModules = NULL;
    }
}

BOOLEAN IsAddressInKernel(ULONG64 address) {
    if (g_SystemModules == NULL || g_SystemModules->NumberOfModules == 0) {
        return FALSE;
    }
    
    PRTL_PROCESS_MODULE_INFORMATION ntoskrnl = &g_SystemModules->Modules[0];
    ULONG64 ntoskrnlStart = (ULONG64)ntoskrnl->ImageBase;
    ULONG64 ntoskrnlEnd = ntoskrnlStart + ntoskrnl->ImageSize;
    
    return (address >= ntoskrnlStart && address < ntoskrnlEnd);
}

BOOLEAN IsAddressInAnyModule(ULONG64 address) {
    if (g_SystemModules == NULL) {
        return FALSE;
    }
    
    for (ULONG i = 0; i < g_SystemModules->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION module = &g_SystemModules->Modules[i];
        ULONG64 moduleStart = (ULONG64)module->ImageBase;
        ULONG64 moduleEnd = moduleStart + module->ImageSize;
        
        if (address >= moduleStart && address < moduleEnd) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Manual mapper detection using FF 25 gadget scanning
VOID DetectManualMappedDrivers(VOID) {
    WCHAR logBuffer[256];
    ULONG totalGadgets = 0;
    ULONG totalPages = 0;
    
    PPHYSICAL_MEMORY_RANGE physicalMemoryRanges = MmGetPhysicalMemoryRanges();
    if (physicalMemoryRanges == NULL) {
        return;
    }
    
    PUCHAR checkBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, 'pmMM');
    if (checkBuffer == NULL) {
        ExFreePool(physicalMemoryRanges);
        return;
    }
    
    for (int i = 0; physicalMemoryRanges[i].BaseAddress.QuadPart || 
                    physicalMemoryRanges[i].NumberOfBytes.QuadPart; i++) {
        
        PHYSICAL_ADDRESS start = physicalMemoryRanges[i].BaseAddress;
        SIZE_T totalSize = (SIZE_T)physicalMemoryRanges[i].NumberOfBytes.QuadPart;
        
        for (SIZE_T offset = 0; offset < totalSize; offset += PAGE_SIZE) {
            PHYSICAL_ADDRESS chunkStart;
            chunkStart.QuadPart = start.QuadPart + offset;
            SIZE_T chunkSize = min(PAGE_SIZE, totalSize - offset);
            
            MM_COPY_ADDRESS address;
            address.PhysicalAddress = chunkStart;
            
            SIZE_T bytesRead;
            NTSTATUS status = MmCopyMemory(
                checkBuffer,
                address,
                chunkSize,
                MM_COPY_MEMORY_PHYSICAL,
                &bytesRead
            );
            
            if (!NT_SUCCESS(status) || bytesRead != chunkSize) {
                continue;
            }
            
            totalPages++;
            
            // Search for FF 25 (jmp qword ptr [rip+offset])
            for (SIZE_T j = 0; j < chunkSize - 6; j++) {
                if (checkBuffer[j] == 0xFF && checkBuffer[j + 1] == 0x25) {
                    ULONG64 physicalFound = chunkStart.QuadPart + j;
                    PVOID virtualFound = MmGetVirtualForPhysical(chunkStart);
                    
                    if (virtualFound == NULL) {
                        continue;
                    }
                    
                    ULONG64 virtualFoundAddr = (ULONG64)virtualFound + j;
                    
                    __try {
                        int instructionOffset = *(int*)(checkBuffer + j + 2);
                        ULONG64 importPtrAddr = virtualFoundAddr + instructionOffset + 6;
                        
                        if (!MmIsAddressValid((PVOID)importPtrAddr)) {
                            continue;
                        }
                        
                        ULONG64 resolved = *(ULONG64*)importPtrAddr;
                        
                        if (resolved == 0) {
                            continue;
                        }
                        
                        if (!IsAddressInKernel(resolved)) {
                            continue;
                        }
                        
                        if (IsAddressInAnyModule(virtualFoundAddr)) {
                            continue;
                        }
                        
                        totalGadgets++;
                        
                        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
                            L"ALERT: Mapped driver at %llx->%llx",
                            virtualFoundAddr, resolved);
                        LogToFile(logBuffer);
                        
                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                    }
                }
            }
        }
    }
    
    ExFreePoolWithTag(checkBuffer, 'pmMM');
    ExFreePool(physicalMemoryRanges);
    
    if (totalGadgets > 0) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"Scan: %d gadgets found in %d pages", totalGadgets, totalPages);
        LogToFile(logBuffer);
    }
}

VOID CheckForAnomalies(PVOID VirtualAddress, PTE Pte) {
    WCHAR logBuffer[256];
    
    if (!Pte.Present && Pte.Accessed) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"ANOM: %p P=0 A=1", VirtualAddress);
        LogToFile(logBuffer);
    }
    
    if (Pte.Present && Pte.Write && Pte.User && !Pte.NoExecute) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"ANOM: %p W+X user (DEP bypass)", VirtualAddress);
        LogToFile(logBuffer);
    }
    
    if (Pte.Present && Pte.Write && !Pte.User && !Pte.NoExecute) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"ANOM: %p W+X kernel", VirtualAddress);
        LogToFile(logBuffer);
    }
    
    if (Pte.Present && Pte.CopyOnWrite && Pte.Write) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"ANOM: %p COW+W", VirtualAddress);
        LogToFile(logBuffer);
    }
    
    if (Pte.Present && Pte.PageFrameNumber == 0) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"ANOM: %p PFN=0", VirtualAddress);
        LogToFile(logBuffer);
    }
}

NTSTATUS WalkPageTable(PVOID VirtualAddress) {
    ULONG64 cr3;
    ULONG64 pml4Index, pdptIndex, pdIndex, ptIndex;
    PTE *pml4, *pdpt, *pd, *pt;
    PTE pml4e, pdpte, pde, pte;
    PHYSICAL_ADDRESS physAddr;
    WCHAR logBuffer[256];
    
    if (VirtualAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    __try {
        cr3 = __readcr3();
        
        pml4Index = PML4_INDEX(VirtualAddress);
        pdptIndex = PDPT_INDEX(VirtualAddress);
        pdIndex = PD_INDEX(VirtualAddress);
        ptIndex = PT_INDEX(VirtualAddress);
        
        physAddr.QuadPart = cr3 & 0xFFFFFFFFF000ULL;
        pml4 = (PTE*)MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
        if (pml4 == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        pml4e = pml4[pml4Index];
        MmUnmapIoSpace(pml4, PAGE_SIZE);
        
        if (!pml4e.Present) {
            return STATUS_UNSUCCESSFUL;
        }
        
        physAddr.QuadPart = (pml4e.PageFrameNumber << 12);
        pdpt = (PTE*)MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
        if (pdpt == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        pdpte = pdpt[pdptIndex];
        MmUnmapIoSpace(pdpt, PAGE_SIZE);
        
        if (!pdpte.Present) {
            return STATUS_UNSUCCESSFUL;
        }
        
        physAddr.QuadPart = (pdpte.PageFrameNumber << 12);
        pd = (PTE*)MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
        if (pd == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        pde = pd[pdIndex];
        MmUnmapIoSpace(pd, PAGE_SIZE);
        
        if (!pde.Present) {
            return STATUS_UNSUCCESSFUL;
        }
        
        physAddr.QuadPart = (pde.PageFrameNumber << 12);
        pt = (PTE*)MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
        if (pt == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        pte = pt[ptIndex];
        MmUnmapIoSpace(pt, PAGE_SIZE);
        
        if (!pte.Present) {
            return STATUS_UNSUCCESSFUL;
        }
        
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"%p P:%d W:%d U:%d NX:%d PFN:%llx",
            VirtualAddress, pte.Present, pte.Write, pte.User, 
            pte.NoExecute, pte.PageFrameNumber);
        LogToFile(logBuffer);
        
        CheckForAnomalies(VirtualAddress, pte);
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}

VOID ScanKernelMemory(VOID) {
    WCHAR logBuffer[256];
    int scannedCount = 0;
    
    ULONG64 kernelAddresses[] = {
        0xFFFFF80000000000ULL,
        0xFFFFF80001000000ULL,
        0xFFFFF80002000000ULL,
        0xFFFFF80010000000ULL,
        0xFFFFF80020000000ULL,
    };
    
    for (int i = 0; i < sizeof(kernelAddresses) / sizeof(ULONG64); i++) {
        PVOID addr = (PVOID)kernelAddresses[i];
        
        if (MmIsAddressValid(addr)) {
            if (NT_SUCCESS(WalkPageTable(addr))) {
                scannedCount++;
            }
        }
    }
    
    if (scannedCount > 0) {
        RtlStringCbPrintfW(logBuffer, sizeof(logBuffer),
            L"Kernel scan: %d addresses", scannedCount);
        LogToFile(logBuffer);
    }
}

VOID ScanThreadRoutine(_In_ PVOID Context) {
    LARGE_INTEGER interval;
    
    UNREFERENCED_PARAMETER(Context);
    
    interval.QuadPart = -20000000LL;
    
    while (!g_StopScanning) {
        NTSTATUS status = KeWaitForSingleObject(
            &g_StopEvent,
            Executive,
            KernelMode,
            FALSE,
            &interval
        );
        
        // Stop event signaled
        if (status == STATUS_SUCCESS) {
            break;
        }
        
        // Double check stop flag
        if (g_StopScanning) {
            break;
        }
        
        // Perform scan
        __try {
            LogToFile(L"--- Scan start ---");
            ScanKernelMemory();
            DetectManualMappedDrivers();
            LogToFile(L"--- Scan end ---");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LogToFile(L"Scan exception");
        }
    }
    
    // Clean thread termination
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS StartAutomaticScanning(VOID) {
    NTSTATUS status;
    HANDLE threadHandle;
    OBJECT_ATTRIBUTES objAttr;
    
    g_StopScanning = FALSE;
    
    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);
    
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &objAttr,
        NULL,
        NULL,
        ScanThreadRoutine,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&g_ScanThread,
        NULL
    );
    
    ZwClose(threadHandle);
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    LogToFile(L"Scanning started (2s interval)");
    
    return STATUS_SUCCESS;
}

VOID StopAutomaticScanning(VOID) {
    LARGE_INTEGER timeout;
    NTSTATUS status;
    
    if (g_ScanThread == NULL) {
        return;
    }
    
    // Set stop flag
    g_StopScanning = TRUE;
    
    // Signal event
    KeSetEvent(&g_StopEvent, IO_NO_INCREMENT, FALSE);
    
    // Wait for thread termination - 15 second timeout
    timeout.QuadPart = -150000000LL; // 15 seconds
    
    status = KeWaitForSingleObject(
        g_ScanThread,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );
    
    // Release thread reference
    ObDereferenceObject(g_ScanThread);
    g_ScanThread = NULL;
    
    // Extra safety delay
    LARGE_INTEGER shortDelay;
    shortDelay.QuadPart = -5000000LL; // 500ms
    KeDelayExecutionThread(KernelMode, FALSE, &shortDelay);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    
    // Stop thread and wait for complete termination
    StopAutomaticScanning();
    
    // Wait for all I/O operations to complete
    LARGE_INTEGER delay;
    delay.QuadPart = -20000000LL; // 2 seconds
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    
    // Cleanup resources
    FreeSystemModules();
    
    // Close log file (last)
    CloseLogFile();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DriverObject->DriverUnload = DriverUnload;
    
    status = InitializeLogFile();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CacheSystemModules();
    if (!NT_SUCCESS(status)) {
        CloseLogFile();
        return status;
    }
    
    status = StartAutomaticScanning();
    if (!NT_SUCCESS(status)) {
        FreeSystemModules();
        CloseLogFile();
        return status;
    }
    
    return STATUS_SUCCESS;
}
