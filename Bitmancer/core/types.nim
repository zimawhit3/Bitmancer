

import 
    types/[api, base, cfg, exceptions, loader, ntmmapi, pe, pebteb, shared, sync]
export 
    api, base, cfg, exceptions, loader, ntmmapi, pe, pebteb, shared, sync

type
    SomeProcIdent*      = cstring|DWORD|WORD
    SomeThunkedIdent*   = cstring|DWORD
    
    ## Distinct pointer for module base addresses.
    ModuleHandle* = distinct pointer

func `==`*(a: ModuleHandle, b: pointer): bool {.borrow.}
func `==`*(a,b: ModuleHandle): bool {.borrow.}
func `isNil`*(a: ModuleHandle): bool {.borrow.}

template `+%`*(h: ModuleHandle, i: SomeInteger): PVOID =
    cast[PVOID](cast[int](h) +% i)

template `-%`*(h: ModuleHandle, i: SomeInteger): PVOID =
    cast[PVOID](cast[int](h) -% i)
