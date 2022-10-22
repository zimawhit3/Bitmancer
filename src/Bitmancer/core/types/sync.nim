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
    base
export
    base

## SRW Locks
##-----------------------------------------------
type
    RTL_SRWLOCK_STRUCT_1* {.pure.} = object
        Locked*         {.bitsize:1.}:  ULONGLONG
        Waiting*        {.bitsize:1.}:  ULONGLONG
        Waking*         {.bitsize:1.}:  ULONGLONG
        MultipleShared* {.bitsize:1.}:  ULONGLONG
        Shared*         {.bitsize:60.}: ULONGLONG

    RTL_SRWLOCK* {.pure, union.} = object
        Struct1*:   RTL_SRWLOCK_STRUCT_1
        Value*:     ULONGLONG
        Ptr*:       PVOID
    PRTL_SRWLOCK* = ptr RTL_SRWLOCK

