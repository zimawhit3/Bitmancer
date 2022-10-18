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

type
    RTL_BALANCED_NODE_CHILD_ENTRY* {.pure.} = object
        Left*:  PRTL_BALANCED_NODE
        Right*: PRTL_BALANCED_NODE

    RTL_BALANCED_NODE_CHILDREN* {.pure, union.} = object
        Children*:      array[2, PRTL_BALANCED_NODE]
        ChildEntry*:    RTL_BALANCED_NODE_CHILD_ENTRY

    RTL_BALANCED_NODE_UNION2* {.pure, union.} = object
        Red*        {.bitsize:1.}:  UCHAR
        Balance*    {.bitsize:2.}:  UCHAR
        ParentValue*:               ULONGLONG

    RTL_BALANCED_NODE* {.pure.} = object
        Children*:  RTL_BALANCED_NODE_CHILDREN
        Union2*:    RTL_BALANCED_NODE_UNION2
    PRTL_BALANCED_NODE* = ptr RTL_BALANCED_NODE

    RTL_RB_TREE* {.pure.} = object
        Root*:  PRTL_BALANCED_NODE
        Min*:   PRTL_BALANCED_NODE

    PRTL_RB_TREE* = ptr RTL_RB_TREE

    LDR_DLL_LOAD_REASON* {.pure.} = enum
        LoadReasonUnknown = -1
        LoadReasonStaticDependency
        LoadReasonStaticForwarderDependency
        LoadReasonDynamicForwarderDependency
        LoadReasonDelayloadDependency
        LoadReasonDynamicLoad
        LoadReasonAsImageLoad
        LoadReasonAsDataLoad
        LoadReasonEnclavePrimary
        LoadReasonEnclaveDependency
        LoadReasonPatchImage

    LDR_HOT_PATCH_STATE* {.pure.} = enum
        LdrHotPatchBaseImage = 0,
        LdrHotPatchNotApplied = 1,
        LdrHotPatchAppliedReverse = 2,
        LdrHotPatchAppliedForward = 3,
        LdrHotPatchFailedToPatch = 4,
        LdrHotPatchStateMax = 5
 
    LDR_DDAG_STATE* {.pure.} = enum
        LdrModulesMerged                    = -5,
        LdrModulesInitError                 = -4,
        LdrModulesSnapError                 = -3,
        LdrModulesUnloaded                  = -2,
        LdrModulesUnloading                 = -1,
        LdrModulesPlaceHolder               = 0,
        LdrModulesMapping                   = 1,
        LdrModulesMapped                    = 2,
        LdrModulesWaitingForDependencies    = 3,
        LdrModulesSnapping                  = 4,
        LdrModulesSnapped                   = 5,
        LdrModulesCondensed                 = 6,
        LdrModulesReadyToInit               = 7,
        LdrModulesInitializing              = 8,
        LdrModulesReadyToRun                = 9

    LDR_SERVICE_TAG_RECORD* {.pure.} = object
        Next*:          PLDR_SERVICE_TAG_RECORD
        ServiceTag*:    ULONG
    PLDR_SERVICE_TAG_RECORD* = ptr LDR_SERVICE_TAG_RECORD

    LDRP_CSLIST* {.pure.} = object
        Tail*: PSINGLE_LIST_ENTRY

    LDR_DDAG_NODE* {.pure.} = object
        ##TODO: order of object fields changes in Windows 8 & 8.1
        Modules*:                   LIST_ENTRY
        ServiceTagList*:            PLDR_SERVICE_TAG_RECORD
        LoadCount*:                 ULONG
        LoadWhileUnloadingCount*:   ULONG
        LowestLink*:                ULONG
        Dependencies*:              LDRP_CSLIST
        IncomingDependencies*:      LDRP_CSLIST
        State*:                     LDR_DDAG_STATE
        CondenseLink*:              SINGLE_LIST_ENTRY
        PreorderNumber*:            ULONG
    PLDR_DDAG_NODE* = ptr LDR_DDAG_NODE

    LDR_DATA_TABLE_ENTRY_UNION_ONE* {.pure, union.} = object
        InInitializationOrderLinks*:    LIST_ENTRY
        InProgressLinks*:               LIST_ENTRY
    PLDR_DATA_TABLE_ENTRY_UNION_ONE* = ptr LDR_DATA_TABLE_ENTRY_UNION_ONE

    LDR_DATA_TABLE_ENTRY_STRUCT_ONE* {.pure.} = object
        PackagedBinary*             {.bitsize:1.}: ULONG
        MarkedForRemoval*           {.bitsize:1.}: ULONG
        ImageDll*                   {.bitsize:1.}: ULONG
        LoadNotificationSent*       {.bitsize:1.}: ULONG
        TelemetryEntryProcessed*    {.bitsize:1.}: ULONG
        ProcessStaticImport*        {.bitsize:1.}: ULONG
        InLegacyLists*              {.bitsize:1.}: ULONG
        InIndexes*                  {.bitsize:1.}: ULONG
        ShimDll*                    {.bitsize:1.}: ULONG
        InExceptionTable*           {.bitsize:1.}: ULONG
        ReservedFlags1*             {.bitsize:2.}: ULONG
        LoadInProgress*             {.bitsize:1.}: ULONG
        when OsVer >= OS_10_Threadhold1:
            LoadConfigProcessed*    {.bitsize:1.}: ULONG
        else:
            ReservedFlags2*         {.bitsize:1.}: ULONG
        EntryProcessed*             {.bitsize:1.}: ULONG
        when OsVer >= OS_8_1_2012R2U1:
            ProtectDelayLoad*       {.bitsize:1.}: ULONG
            ReservedFlags3*         {.bitsize:2.}: ULONG
        else:
            ReservedFlags3*         {.bitsize:3.}: ULONG
        DontCallForThreads*         {.bitsize:1.}: ULONG
        ProcessAttachCalled*        {.bitsize:1.}: ULONG
        ProcessAttachFailed*        {.bitsize:1.}: ULONG
        CorDeferredValidate*        {.bitsize:1.}: ULONG
        CorImage*                   {.bitsize:1.}: ULONG
        DontRelocate                {.bitsize:1.}: ULONG
        CorILOnly*                  {.bitsize:1.}: ULONG
        when OSVer >= OS_11_InsiderPreview:
            ChpeImage*              {.bitsize:1.}: ULONG
            ChpeEmulatorImage*      {.bitsize:1.}: ULONG
            ReservedFlags5*         {.bitsize:1.}: ULONG
        elif OsVer >= OS_10_Redstone4:
            ChpeImage*              {.bitsize:1.}: ULONG
            ReservedFlags5*         {.bitsize:2.}: ULONG
        else:
            ReservedFlags5*         {.bitsize:3.}: ULONG
        Redirected*                 {.bitsize:1.}: ULONG
        ReservedFlags6*             {.bitsize:2.}: ULONG
        CompatDatabaseProcessed*    {.bitsize:1.}: ULONG

    LDR_DATA_TABLE_ENTRY_UNION_TWO* {.pure, union.} = object
        FlagGroup*: array[4, UCHAR]
        Flags*:     ULONG
        Struct1*:   LDR_DATA_TABLE_ENTRY_STRUCT_ONE
    PLDR_DATA_TABLE_ENTRY_UNION_TWO* = ptr LDR_DATA_TABLE_ENTRY_UNION_TWO
    
    LDR_DATA_TABLE_ENTRY* {.pure.} = object
        InLoadOrderLinks*:              LIST_ENTRY
        InMemoryOrderLinks*:            LIST_ENTRY
        when Osver >= OS_10_Threadhold1:
            InInitializationOrderLinks*: LIST_ENTRY
        else:
            Union_1*:                   LDR_DATA_TABLE_ENTRY_UNION_ONE
        DLLBase*:                       PVOID
        EntryPoint*:                    PVOID
        SizeOfImage*:                   ULONG
        FullDllName*:                   UNICODE_STRING
        BaseDllName*:                   UNICODE_STRING
        Union_2*:                       LDR_DATA_TABLE_ENTRY_UNION_TWO
        ObsoleteLoadCount*:             USHORT
        TlsIndex*:                      USHORT
        HashLinks*:                     LIST_ENTRY
        TimeDateStamp*:                 ULONG
        EntryPointActivationContext*:   PVOID   #PACTIVATION_CoNTEXT
        when OsVer >= OS_10_Threadhold1:
            Lock*:                      PVOID
        else:
            PatchInformation*:          PVOID
        DdagNode*:                      PLDR_DDAG_NODE
        NodeModuleLink*:                LIST_ENTRY
        SnapContext*:                   PVOID       # PLDRP_LOAD_CONTEXT
        ParentDllBase*:                 PVOID
        SwitchBackContext*:             PVOID
        BaseAddressIndexNode*:          RTL_BALANCED_NODE
        MappingInfoIndexNode*:          RTL_BALANCED_NODE
        OriginalBase*:                  ULONG_PTR
        LoadTime*:                      LARGE_INTEGER
        BaseNameHashValue*:             ULONG
        LoadReason*:                    LDR_DLL_LOAD_REASON
        when OsVer >= OS_8_1_2012R2RTM:
            ImplicitPathOptions*:       ULONG
            when OsVer >= OS_10_Threadhold1:
                ReferenceCount*:        ULONG
                when OsVer >= OS_10_Redstone:
                    DependentLoadFlags*: ULONG
                    when OsVer >= OS_10_Redstone2:
                        SigningLevel*:  UCHAR
                        when OsVer >= OS_11_InsiderPreview:
                            CheckSum*:  ULONG
                            ActivePatchImageBase*: PVOID
                            HotPatchState*: LDR_HOT_PATCH_STATE
                
    PLDR_DATA_TABLE_ENTRY* = ptr LDR_DATA_TABLE_ENTRY

