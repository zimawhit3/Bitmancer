##---------------------------------------------------------------------
##      Bitmancer - a library for Offensive Security Development 
##           
##          Copyright (C) 2022  B. Marshall (zimawhite1@gmail.com)
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <https://www.gnu.org/licenses/>.
## 
##----------------------------------------------------------------------------------
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