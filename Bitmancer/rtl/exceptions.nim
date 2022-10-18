

import
    ../core

export 
    core

## InvertedFunctionTable
##------------------------------------    
func cRtlpInsertInvertedFuncTableEntry*(Ift: PINVERTED_FUNCTION_TABLE, imageBase: ModuleHandle, imageSz: SIZE_T): NtResult[void] =
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
    
func cRtlpRemoveInvertedFuncTableEntry*(Ift: PINVERTED_FUNCTION_TABLE, imageBase: ModuleHandle) =
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
