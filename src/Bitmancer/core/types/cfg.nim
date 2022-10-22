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
const
    ## Module performs control flow integrity checks using system-supplied support
    IMAGE_GUARD_CF_INSTRUMENTED*                    = 0x00000100 

    ## Module performs control flow and write integrity checks
    IMAGE_GUARD_CFW_INSTRUMENTED*                   = 0x00000200 

    ## Module contains valid control flow target metadata
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT*          = 0x00000400 

    ## Module does not make use of the /GS security cookie
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED*             = 0x00000800 

    ## Module supports read only delay load IAT
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT*              = 0x00001000 
    
    ## Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION*   = 0x00002000

    ## Module contains suppressed export information
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT* = 0x00004000

    ## Module enables suppression of exports
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION*       = 0x00008000

    ## Module contains longjmp target information
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT*          = 0x00010000

    ## Module contains return flow instrumentation and metadata
    IMAGE_GUARD_RF_INSTRUMENTED*                    = 0x00020000

    ## Module requests that the OS enable return flow protection
    IMAGE_GUARD_RF_ENABLE*                          = 0x00040000

    ## Module requests that the OS enable return flow protection in strict mode
    IMAGE_GUARD_RF_STRICT*                          = 0x00080000

    ## Module was built with retpoline support
    IMAGE_GUARD_RETPOLINE_PRESENT*                  = 0x00100000

    ## Stride of Guard CF function table encoded in these bits (additional count of bytes per element)
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK*        = 0xF0000000

    ## Shift to right-justify Guard CF function table stride
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT*       = 28
