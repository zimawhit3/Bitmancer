

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

proc eRtlRbInsertNodeEx*( 
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

proc eRtlRbRemoveNode*(pRtlRbTree: PRTL_RB_TREE, node: PRTL_BALANCED_NODE): NtResult[void] =
    let 
        Ntdll               = ? NTDLL_BASE()
        pRtlRbRemoveNode    = ? getRtlRbRemoveNode Ntdll
    pRtlRbRemoveNode(pRtlRbTree, node)
    ok()

## Rtl*BaseAddressIndex
##------------------------------------
proc RtlInsertNodeBaseAddressIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] =
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
    eRtlRbInsertNodeEx(BaseAddressIndex, addr LdrEntry.BaseAddressIndexNode, bRight, addr imageEntry.BaseAddressIndexNode)

proc RtlRemoveNodeBaseAddressIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] =
    let BaseAddressIndex = ? getBaseAddressIndexTree()
    eRtlRbRemoveNode(BaseAddressIndex, addr imageEntry.BaseAddressIndexNode)

## Rtl*MappingInfoIndex
##------------------------------------
proc RtlInsertNodeMappingInfoIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] =
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
    eRtlRbInsertNodeEx(MappingInfoIndex, addr LdrEntry.MappingInfoIndexNode, bRight, addr imageEntry.MappingInfoIndexNode)

proc RtlRemoveNodeMappingInfoIndex*(imageEntry: PLDR_DATA_TABLE_ENTRY): NtResult[void] {.discardable.} =
    let MappingInfoIndex = ? getMappingInfoIndexTree()
    eRtlRbRemoveNode(MappingInfoIndex, addr imageEntry.MappingInfoIndexNode)

