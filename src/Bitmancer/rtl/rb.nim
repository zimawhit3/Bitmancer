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
    ../core/obfuscation/hash,
    ../core

export
    core

## Hashes
##---------------------------------------------------------------------
const
    RtlRbInsertNodeExHash*  = ctDjb2 "RtlRbInsertNodeEx"
    RtlRbRemoveNodeHash*    = ctDjb2 "RtlRbRemoveNode"

## RtlRbInsertNodeEx
##------------------------------------
proc getRtlRbInsertNodeEx*(Ntdll: ModuleHandle): NtResult[RtlRbInsertNodeEx] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlRbInsertNodeExHash)
    ok cast[RtlRbInsertNodeEx](f)

proc rtlRbInsertNodeEx*( 
    pRtlRbTree: PRTL_RB_TREE, 
    parent: PRTL_BALANCED_NODE, 
    bRight: BOOLEAN, 
    node: PRTL_BALANCED_NODE
): NtResult[void] =
    let 
        Ntdll               = ? NTDLL_BASE()
        pRtlRbInsertNodeEx  = ? getRtlRbInsertNodeEx Ntdll
    pRtlRbInsertNodeEx(pRtlRbTree, parent, bRight, node)
    ok()

## RtlRbRemoveNode
##------------------------------------
proc getRtlRbRemoveNode*(Ntdll: ModuleHandle): NtResult[RtlRbRemoveNode] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlRbRemoveNodeHash)
    ok cast[RtlRbRemoveNode](f)

proc rtlRbRemoveNode*(pRtlRbTree: PRTL_RB_TREE, node: PRTL_BALANCED_NODE): NtResult[void] =
    let 
        Ntdll               = ? NTDLL_BASE()
        pRtlRbRemoveNode    = ? getRtlRbRemoveNode Ntdll
    pRtlRbRemoveNode(pRtlRbTree, node)
    ok()

## Rtl*BaseAddressIndex
##------------------------------------
proc rtlInsertNodeBaseAddressIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] =
    let
        BaseAddressIndex    = ? getBaseAddressIndexTree()
        BaseNodeOffset      = offsetOf(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode)
    var 
        bRight      = BOOLEAN(FALSE)
        LdrEntry    = cast[PLDR_DATA_TABLE_ENTRY](cast[int](BaseAddressIndex) -% BaseNodeOffset)        
    
    while true:
        if imageEntry.DLLBase < LdrEntry.DllBase:
            if CHILD_ENTRY_LEFT(LdrEntry.BaseAddressIndexNode).isNil():
                break
            LdrEntry = ENTRY_NEXT_NODE_LEFT(LdrEntry.BaseAddressIndexNode, BaseNodeOffset)
            
        elif imageEntry.DLLBase > LdrEntry.DllBase:
            if CHILD_ENTRY_RIGHT(LdrEntry.BaseAddressIndexNode).isNil():
                bRight = TRUE
                break
            LdrEntry = ENTRY_NEXT_NODE_RIGHT(LdrEntry.BaseAddressIndexNode, BaseNodeOffset)
            
        else:
            ## Already in the tree, inc the ref count
            inc LdrEntry.DdagNode.LoadCount 
            return ok()
    rtlRbInsertNodeEx(BaseAddressIndex, addr LdrEntry.BaseAddressIndexNode, bRight, addr imageEntry.BaseAddressIndexNode)

proc rtlRemoveNodeBaseAddressIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] =
    let BaseAddressIndex = ? getBaseAddressIndexTree()
    rtlRbRemoveNode(BaseAddressIndex, addr imageEntry.BaseAddressIndexNode)

## Rtl*MappingInfoIndex
##------------------------------------
proc rtlInsertNodeMappingInfoIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] =
    let
        MappingInfoIndex    = ? getMappingInfoIndexTree()
        NtHeaders           = ? imageNtHeader imageEntry.DLLBase.ModuleHandle
        TimeStamp           = NtHeaders.FileHeader.TimeDateStamp
        MappingNodeOffset   = offsetOf(LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode)
    var
        bRight   = BOOLEAN(FALSE)       
        LdrEntry = cast[PLDR_DATA_TABLE_ENTRY](cast[int](MappingInfoIndex) -% MappingNodeOffset)
    
    while true:
        if TimeStamp <=% LdrEntry.TimeDateStamp and 
           (TimeStamp != LdrEntry.TimeDateStamp or NtHeaders.OptionalHeader.SizeOfImage <= LdrEntry.SizeOfImage):
            if CHILD_ENTRY_LEFT(LdrEntry.MappingInfoIndexNode).isNil():
                break
            LdrEntry = ENTRY_NEXT_NODE_LEFT(LdrEntry.MappingInfoIndexNode, MappingNodeOffset)

        elif TimeStamp >=% LdrEntry.TimeDateStamp and 
             (TimeStamp != LdrEntry.TimeDateStamp or NtHeaders.OptionalHeader.SizeOfImage >= LdrEntry.SizeOfImage):
            if CHILD_ENTRY_RIGHT(LdrEntry.MappingInfoIndexNode).isNil():
                bRight = TRUE
                break
            LdrEntry = ENTRY_NEXT_NODE_RIGHT(LdrEntry.MappingInfoIndexNode, MappingNodeOffset)
        
        else:
            ## Already in the tree, inc the ref count
            inc LdrEntry.DdagNode.LoadCount 
            return ok()
    rtlRbInsertNodeEx(MappingInfoIndex, addr LdrEntry.MappingInfoIndexNode, bRight, addr imageEntry.MappingInfoIndexNode)

proc rtlRemoveNodeMappingInfoIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] {.discardable.} =
    let MappingInfoIndex = ? getMappingInfoIndexTree()
    rtlRbRemoveNode(MappingInfoIndex, addr imageEntry.MappingInfoIndexNode)

