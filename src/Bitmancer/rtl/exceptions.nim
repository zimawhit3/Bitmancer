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

## InvertedFunctionTable
##------------------------------------    
func rtlpInsertInvertedFuncTableEntry*(Ift: PINVERTED_FUNCTION_TABLE, imageBase: ModuleHandle, imageSz: SIZE_T): NtResult[void] =
    var index = ULONG(0)
    if Ift.CurrentSize != Ift.MaximumSize:

        if Ift.CurrentSize != 0:            
            while index < Ift.CurrentSize:
                ## NTDLL Must be at index 0!
                if index != 0 and cast[int](imageBase) < cast[int](Ift.TableEntries[index].ImageBase):
                    break
                inc index
            if index != Ift.CurrentSize:
                moveMemory(
                    addr Ift.TableEntries[index+1],
                    addr Ift.TableEntries[index],
                    (Ift.CurrentSize - index) * sizeof(INVERTED_FUNCTION_TABLE_ENTRY)
                )
        let ExcDirHeaders = ? getExceptionDirectoryHeader(imageBase)
        Ift.TableEntries[index].Union1.FunctionTable = EXCEPTION_DIRECTORY(imageBase, ExcDirHeaders)
        Ift.TableEntries[index].ImageBase            = PVOID(imageBase)
        Ift.TableEntries[index].SizeOfImage          = DWORD(imageSz)
        Ift.TableEntries[index].SizeOfTable          = ExcDirHeaders.Size
    else:
        Ift.OverFlow = TRUE
    ok()
    
func rtlpRemoveInvertedFuncTableEntry*(Ift: PINVERTED_FUNCTION_TABLE, imageBase: ModuleHandle) =
    for index in 0 ..< Ift.CurrentSize:
        if imageBase == Ift.TableEntries[index].ImageBase:
            if Ift.CurrentSize != 1:
                moveMemory(
                    addr Ift.TableEntries[index],
                    addr Ift.TableEntries[index+1],
                    (Ift.CurrentSize - index - 1) * sizeof INVERTED_FUNCTION_TABLE_ENTRY
                )
            dec Ift.CurrentSize
    if Ift.CurrentSize != Ift.MaximumSize:
        Ift.OverFlow = FALSE
