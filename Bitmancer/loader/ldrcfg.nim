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
    ldrbase

export
    ldrbase

## Loader's Control Flow Guard routines
##------------------------------------------------------------------------

## Security Cookie
##------------------------------------
proc ldrGenSecurityCookie(): NtResult[UINT_PTR] =
    var 
        cookie      = UINT_PTR 0
        perfCounter = LARGE_INTEGER()
    let time        = GetSystemTime()
    ? eNtQueryPerformanceCounter(perfCounter, NULL)
    cookie = cast[UINT_PTR]((time.QuadPart shr 32) xor time.QuadPart)
    cookie ^= GetProcessId()
    cookie ^= GetThreadId()
    cookie ^= GetTickCount() 
    when defined(cpu64):
        cookie ^= perfCounter.QuadPart
    else:
        cookie ^= perfCounter.LowPart
        cookie ^= perfCounter.HighPart
    ok cookie

proc ldrSetSecurityCookie(ctx: PLoadContext): NtResult[void] =
    let 
        imageBase   = ctx.entry.DLLBase.ModuleHandle
        NtHeaders   = ? imageNtHeader(imageBase)    
        lcHeader    = getLoadConfigDirectoryHeader imageBase
    
    if lcHeader.isErr():
        if lcHeader.error() in {DirectoryEmpty, DirectoryNotFound}:
            return ok()
        return err lcHeader.error()
      
    #let LoadConfig = cast[PIMAGE_LOAD_CONFIG_DIRECTORY](ctx.entry.DLLBase +! loadConfigDir.VirtualAddress)
    #if loadConfig.Size < offsetOf(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) +% sizeof(LoadConfig.SecurityCookie):
    #    return err ImageInvalid

    let LoadConfig = LOAD_CONFIG_DIRECTORY(imageBase, lcHeader.get())
    ## Check LoadConfig's OS Versioning
    ## TODO
    
    ## Check if DLL uses Securiy Cookie
    if LoadConfig.GuardFlags && IMAGE_GUARD_SECURITY_COOKIE_UNUSED or LoadConfig.SecurityCookie == 0:
        return ok()
    
    ## Check if Cookie is out of bounds
    if cast[PBYTE](addr LoadConfig.SecurityCookie) < cast[PBYTE](ctx.entry.DLLBase) or 
       cast[PBYTE](addr LoadConfig.SecurityCookie) >= cast[PBYTE](ctx.entry.DLLBase +! NtHeaders.OptionalHeader.SizeOfImage):
        return err ImageInvalid
    
    ## If Cookie is zero (not desired) or Cookie already set, return ok
    if LoadConfig.SecurityCookie != SECURITY_COOKIE_INITIAL or LoadConfig.SecurityCookie != SECURITY_COOKIE_16BIT_INITIAL:
        return ok()

    var newCookie = ? ldrGenSecurityCookie()

    ## only low 16 bits are needed
    if LoadConfig.SecurityCookie == SECURITY_COOKIE_16BIT_INITIAL:
        newCookie &= 0xFFFF

    ## if cookie matches, make it different
    if newCookie == SECURITY_COOKIE_INITIAL or newCookie == SECURITY_COOKIE_16BIT_INITIAL:
        inc newCookie

    when defined(cpu64):
        newCookie &= 0x0000FFFFFFFFFFFF
    
    LoadConfig.SecurityCookie = newCookie
    ok()

proc ldrProcessCFG(ctx: PLoadContext): NtResult[void] =
    let NtHeaders = ? imageNtHeader ctx.entry.DllBase.ModuleHandle
    if NtHeaders.OptionalHeader.DLLCharacteristics && IMAGE_DLLCHARACTERISTICS_GUARD_CF:
        ## Set the Security Cookie, if required
        ? ldrSetSecurityCookie ctx
    ok()

## Public
##------------------------------------
proc ldrCfgProcessLoadConfig*(ctx: PLoadContext): NtResult[void] =
    ? ldrProcessCFG ctx
    ctx.entry.setBit(LoadConfigProcessed)
    ok()
