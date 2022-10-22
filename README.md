# Bitmancer
Bitmancer is a library for Offensive Security Tooling development for the Windows operating system written in Nim. It aims to provide common APIs, routines, and macros with highly configurable, position-independent, standalone implementations. 

If you're looking to develop an Implant, test a quick PoC, or write a brand new shiny tool - Bitmancer can help you get started!

:warning: This repository is currently a massive WIP! There may be issues using it and there are no gaurantees of stability for the time being. :warning:

## Dependencies
Bitmancer partially uses [winim](https://github.com/khchen/winim) for its types. To install, run:   

`nimble install winim`

## Installation
Bitmancer is not yet part of the nimble repository. For the timebeing, you can install it from Github by simply running:  

`nimble install https://github.com/zimawhit3/Bitmancer`

## Compiling
MingW and Nim will introduce dependencies on MSVCRT and Kernel32, as well as global variables used by Nim's System module. If you want to avoid these for position independent code, use the provided nim.cfg.

To compile:
`nim c -d:mingw <Your_Nim_File>`

## Usage
For all modules:
```nim 
import Bitmancer
```
If you need don't need NTDLL routines or syscalls, you can simply use:
```nim
import Bitmancer/core
```

For just the hashing procedures:
```nim
import Bitmancer/core/obfuscation/hash
```

## Current TODOs:
* [ ] Compile Time defines simplified (YAML?)
* [ ] CI/CD
* [ ] Examples
* [ ] Documentation
* [x] Larger compile-time Hash Seed
* [ ] Tests!

## Features
### Currently supported features:
* ApiSet Name Resolving
* Common APIs (GetProcAddress, GetModuleHandle, GetSystemTime, etc..)
* Hashing 
  * Compile Time
  * Run Time
* Manual Mapper
  * From Disk
  * From Memory :construction:
    * DLLs :construction:
    * COFFs :construction:
* NTDLL
  * Nt* Syscalls
  * Rtl* procedures
* NTLoader Database
  * Linked Lists (LDR_DATA_TABLE_ENTRY)
  * Red Black Trees (RTL_BALANCED_NODE)
* Portable Executable parsing and utilities
* SSN Enumeration
  * [Hell's Gate](https://github.com/am0nsec/HellsGate)
  * [Halo's Gate](https://sektor7.net/#!res/2021/halosgate.md)
  * [Tartarus' Gate](https://github.com/trickster0/TartarusGate)
  * [LdrThunkSignatures](https://github.com/mdsecactivebreach/ParallelSyscalls/)
  * ZwCounter
* Stack Strings
* Syscall Evasion Techniques
  * Direct Syscalls
  * Indirect Syscalls

### Future Features I'm aiming to support:
* [ ] Anti-Debug Routines and Utilities
* [ ] Encryption
* [ ] Exception Handling
* [ ] Callbacks
  * [ ] Instrumented
  * [ ] Native
  * [ ] VEH
* [ ] Hooking Routines and Utilities
* [ ] More NTDLL Wrappers
* [ ] Sleep Evasion Techniques
  * [ ] [Death Sleep](https://github.com/janoglezcampos/DeathSleep)
  * [ ] [CreateTimerQueueTimer](https://github.com/Cracked5pider/Ekko)
* [ ] Stack Spoofing
* [ ] Syscall Evasion Techniques
  * [ ] [Tamper](https://github.com/rad9800/TamperingSyscalls)
* [ ] x86 Support

If there's a feature/technique you would like implemented, let me know!

## Examples
Stack Strings:
```nim
var wStr {.stackStringW.} = "Hello!"
var cStr {.stackStringA.} = "World!"
```

If you're looking to generate a wrapper around a syscall not currently available, the basic flow is as follows:
```nim
## Import syscalls
import Bitmancer/syscalls

## For hashing
import Bitmancer/core/obfuscation/hash

## Define your type
type NtClose = proc(h: HANDLE): NTSTATUS {.stdcall, gcsafe.}

## Generate the wrapper
genSyscall(NtClose)

## Define configurations for how to retrieve and execute the syscall

## The procedure's symbol enumeration method - available options are:
## UseEAT - use the export address table to resolve the symbol
## UseIAT - use the import address table to resolve the symbol
## UseLdrThunks - use the NTLoader's LdrThunkSignatures to map a clean NTDLL to resolve symbols from
const symEnum = SymbolEnumeration.UseEAT

## The SSN enumeration method - available options are:
## HellsGate
## HalosGate
## TartarusGate
## ZwCounter
const ssnEnum = SsnEnumeration.HellsGate

## Finally, the execution method - available options are:
## Direct   - use the direct syscall stub
## Indirect - use the indirect syscall stub
const exeEnum = SyscallExecution.Indirect

## Define an ident to use to identify the symbol
const NtCloseHash = ctDjb2 "NtClose"

## Retrive NTDLL
let Ntdll = ? NTDLL_BASE()

## Call ctGetNtSyscall, retrieving the NtSyscall object containing the SSN, pointer to the address of the function
## and a casted stub to your type.
let NtSyscall = ctGetNtSyscall[NtClose](Ntdll, ModuleHandle(NULL), NtCloseHash, symEnum, ssnEnum, exeEnum)

## Finally, call the wrapper!
NtCloseWrapper(h, NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction)
```
See the [runShellCode example](./examples/runShellcode.nim) for a complete example.  
More examples can also be found in [ntdll](./Bitmancer/ntdll/).
