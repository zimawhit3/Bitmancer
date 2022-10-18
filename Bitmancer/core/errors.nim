

import
    results

export
    results

type
    NtError* {.pure.} = enum
        ## Generic Errors
        ##-------------
        InsufficientMemory
        InvalidBuffer
        InvalidBufferSize
        InvalidFlags
        SearchNotFound
        RedBlackTreeError
        RBTreeNotFound
        ## PE Errors
        ##-------------
        ## Directory
        DirectoryEmpty
        DirectoryNotFound
        DirectoryIndexOOB
        
        ## Imports
        ImageInvalid
        
        ## Locks
        LockNotFound
        
        ## Procedures
        ProcedureNotFound
        ProcedureFailure
        ProcedureForwardApiSet
        
        ## Sections
        SectionEmpty
        SectionNotFound

        ## Syscall Errors
        ##-------------
        SignaturesNotFound
        SyscallNotFound
        SyscallFailure

        ## Loader Errors
        ##-------------
        LdrEntryNotFound
        LdrLinkFailed
        LdrUnlinkFailed

        ApiSetSchemaNotSupported
        ApiSetNotFound

    NtResult*[T] = Result[T, NtError]