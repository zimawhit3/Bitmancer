
import
    ../core/obfuscation/hash,
    ../core/[ntloader, procedures]

export
    ntloader

## IO 
## 
## This is still a large WIP. 
##------------------------------------------------------------------------

const
    O_BINARY*           = 0x8000
    LoadLibraryHash*    = ctDjb2 "LoadLibraryA"
    Iob_funcHash*       = ctDjb2 "__iob_func"
    FilenoHash*         = ctDjb2 "_fileno"
    FwriteHash*         = ctDjb2 "fwrite"
    FflushHash*         = ctDjb2 "fflush"
    SetModeHash*        = ctDjb2 "_setmode"

proc getiob_func*(imageBase: ModuleHandle): NtResult[iob_func] {.inline.} =
    let f = ? getProcAddress(imageBase, Iob_funcHash)
    ok cast[iob_func](f)

proc getfileno*(imageBase: ModuleHandle): NtResult[fileno] {.inline.} =
    let f = ? getProcAddress(imageBase, FilenoHash)
    ok cast[fileno](f)

proc getset_mode*(imageBase: ModuleHandle): NtResult[set_mode] {.inline.} =
    let f = ? getProcAddress(imageBase, SetModeHash)
    ok cast[set_mode](f)

proc getfwrite*(imageBase: ModuleHandle): NtResult[fwrite] {.inline.} =
    let f = ? getProcAddress(imageBase, FwriteHash)
    ok cast[fwrite](f)

proc getfflush*(imageBase: ModuleHandle): NtResult[fflush] {.inline.} =
    let f = ? getProcAddress(imageBase, FflushHash)
    ok cast[fflush](f)

proc getAndInitStdout(crtBase: ModuleHandle): NtResult[CFilePtr] =
    let 
        piob_func   = ? getiob_func crtBase
        pfile_no    = ? getfileno crtBase
        pset_mode   = ? getset_mode crtBase

    ## I have no idea why stdout is at an offset of 0x30, the structure 
    ## (from what i can tell by reading mingw's source code) is 0x40 bytes. 
    ## 0x30 puts us at CFile.bufSize.
    let cstdout = cast[CFilePtr](cast[int](piob_func()) +% 0x30)
    if pset_mode(pfile_no(cstdout), O_BINARY) == -1:
        err ProcedureFailure
    else:
        ok cstdout

proc writeStream(crtBase: ModuleHandle, f: CFilePtr, s: cstring): NtResult[void] =
    let
        pfwrite     = ? getfwrite crtBase
        pflush      = ? getfflush crtBase
    discard pfwrite(s, 1, s.len, f)
    discard pflush(f)
    ok()

proc getCrtBase(): NtResult[ModuleHandle] =
    let crtBase =
        if not MODULE_LOADED(MsvcrtHash, LoadOrder):
            ## if not loaded, load it - just using loadlibrary for now
            var msvcrt {.stackStringA.} = "msvcrt.dll"
            let 
                k32             = ? KERNEL32_BASE()
                loadLibrary     = ? getProcAddress(k32, LoadLibraryHash)
                pLoadLibrary    = cast[LoadLibrary](loadlibrary)
            cast[ModuleHandle](pLoadLibrary(cast[LPCSTR](addr msvcrt[0])))
        else:
            ? CRT_BASE()

    if crtBase.isNil():
        err ProcedureNotFound
    else:
        ok crtBase

proc rawWriteStdOut*(s: cstring): NtResult[void] {.discardable.} =
    ## runtime writing to stdout, useful for debugging
    let 
        crtBase     = ? getCrtBase()
        cstdout     = ? getAndInitStdout(crtBase)
    writeStream(crtBase, cstdout, s)

