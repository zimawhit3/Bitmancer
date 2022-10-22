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
    winim/inc/windef,
    winim/utils

## Not sure how else to do this without copying out part of winim's base. 
export windef except PLDR_DATA_TABLE_ENTRY, PPEB_LDR_DATA, LDR_DATA_TABLE_ENTRY, PNT_TIB, NT_TIB, EXCEPTION_REGISTRATION_RECORD,
                    PPEB, PEB, TEB, PTEB, PROCESS_BASIC_INFORMATION, PPROCESS_BASIC_INFORMATION, PEB_LDR_DATA, RtlPcToFileHeader,
                    RtlInitAnsiString, RtlAnsiStringToUnicodeString, RtlAllocateHeap, RtlFreeHeap, RtlInitUnicodeString, NtQuerySystemTime,
                    RtlHashUnicodeString, RtlFreeUnicodeString, PIMAGE_LOAD_CONFIG_DIRECTORY, RtlDeleteFunctionTable, NtQuerySystemInformation,
                    PSYSTEM_BASIC_INFORMATION, SYSTEM_BASIC_INFORMATION, SYSTEM_INFORMATION_CLASS, MEMORY_INFORMATION_CLASS,
                    PRTL_SRWLOCK, RTL_SRWLOCK, RtlAddVectoredExceptionHandler, NtClose, NtOpenFile, RtlCopyMemory, RtlMoveMemory,
                    RtlCompareMemory, LoadLibrary, PRTL_USER_PROCESS_PARAMETERS, RTL_USER_PROCESS_PARAMETERS, NT_ERROR,
                    RtlCreateHeap, NtOpenSection
export utils

type
    WindowsOSVersion* = enum
        OS_8_1_2012RTM
        OS_8_1_2012R2RTM
        OS_8_1_2012R2U1
        OS_10_Threadhold1
        OS_10_Threshold2
        OS_10_Redstone
        OS_10_Redstone2
        OS_10_Redstone3
        OS_10_Redstone4
        OS_10_Redstone5
        OS_10_19H1
        OS_10_19H2
        OS_10_20H1
        OS_10_20H2
        OS_10_21H1
        OS_10_21H2
        OS_11_InsiderPreview
        OS_11_21H2

const 
    OsVer* {.intDefine.} = OS_10_21H1


