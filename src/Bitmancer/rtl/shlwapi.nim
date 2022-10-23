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
    ../core
export
    core

func pathFindFileNameW*(path: LPCWSTR): NtResult[LPCWSTR] =
    if not path.isNil():
        var 
            tmp = cast[ptr UncheckedArray[WCHAR]](path)
            i   = 0
        result = ok path
        while tmp[i] != 0:
            if (tmp[i] == TEXTW('\\') or tmp[i] == TEXTW(':') or tmp[i] == TEXTW('/')) and (tmp[i+1] != 0) and 
                (tmp[i+1] != TEXTW('\\')) and (tmp[i+1] != TEXTW('/')):
                result = ok cast[LPCWSTR](addr tmp[i+1])
            if (tmp[i] == TEXTW('\\') and tmp[i+1] == 0):
                return ok path
            inc i     
    else:
        result = err InvalidBuffer
