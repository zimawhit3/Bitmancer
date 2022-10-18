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
    apiset
export 
    apiset

## PEB
##-----------------------------------------------
type
    RTL_CURDIR* {.pure.} = object
        DosPath*:   UNICODE_STRING
        Handle*:    PVOID

    RTL_DRIVE_LETTER_CURDIR* {.pure.} = object
        Flags*:     USHORT
        Length*:    USHORT
        TimeStamp*: ULONG
        DosPath*:   STRING

    RTL_USER_PROCESS_PARAMETERS* {.pure.} = object
        MaximumLength*:         ULONG
        Length*:                ULONG
        Flags*:                 ULONG
        DebugFlags*:            ULONG
        ConsoleHandle*:         PVOID
        ConsoleFlags*:          ULONG
        StandardInput*:         PVOID
        StandardOutput*:        PVOID
        StandardError*:         PVOID
        CurrentDirectory*:      RTL_CURDIR
        DllPath*:               UNICODE_STRING
        ImagePathName*:         UNICODE_STRING
        CommandLine*:           UNICODE_STRING
        Environment*:           PVOID
        StartingX*:             ULONG
        StartingY*:             ULONG
        CountX*:                ULONG
        CountY*:                ULONG
        CountCharsX*:           ULONG
        CountCharsY*:           ULONG
        FillAttribute*:         ULONG
        WindowFlags*:           ULONG
        ShowWindowFlags*:       ULONG
        WindowTitle*:           UNICODE_STRING
        DesktopInfo*:           UNICODE_STRING
        ShellInfo*:             UNICODE_STRING
        RuntimeData*:           UNICODE_STRING
        CurrentDirectores*:     array[32, RTL_DRIVE_LETTER_CURDIR]
        EnvironmentSize*:       ULONGLONG
        EnvironmentVersion*:    ULONGLONG
        PackageDependencyData*: PVOID
        ProcessGroupId*:        ULONG
        LoaderThreads*:         ULONG
        RedirectionDllName*:    UNICODE_STRING
        HeapPartitionName*:     UNICODE_STRING
        DefaultThreadpoolCpuSetMasks*:      PULONGLONG
        DefaultThreadpoolCpuSetMaskCount*:  ULONG
        DefaultThreadpoolThreadMaximum*:    ULONG

    PRTL_USER_PROCESS_PARAMETERS* = ptr RTL_USER_PROCESS_PARAMETERS

    PEB_BITFIELD* {.pure, union.} = object
        ImageUsesLargePages*            {.bitsize:1.}:  UCHAR
        IsProtectedProcess*             {.bitsize:1.}:  UCHAR
        when OsVer == OS_8_1_2012RTM:
            IsLegacyProcess*            {.bitsize:1.}:  UCHAR
        IsImageDynamicallyRelocated*    {.bitsize:1.}:  UCHAR
        SkipPatchingUser32Forwarders*   {.bitsize:1.}:  UCHAR
        IsPackagedProcess*              {.bitsize:1.}:  UCHAR
        IsAppContainer*                 {.bitsize:1.}:  UCHAR
        when OsVer >= OS_8_1_2012R2RTM:
            IsProtectedProcessLight*    {.bitsize:1.}:  UCHAR
        IsLongPathAwareProcess*         {.bitsize:1.}:  UCHAR

    PEB_CROSSPROCESSFLAGS* {.pure, union.} = object
        ProcessInJob*                   {.bitsize:1.}:  ULONG
        ProcessInitializing*            {.bitsize:1.}:  ULONG
        ProcessUsingVEH*                {.bitsize:1.}:  ULONG
        ProcessUsingVCH*                {.bitsize:1.}:  ULONG
        ProcessUsingFTH*                {.bitsize:1.}:  ULONG
        when OsVer >= OS_10_Redstone5:
            ProcessPreviouslyThrottled* {.bitsize:1.}:  ULONG
            ProcessCurrentlyThrottled*  {.bitsize:1.}:  ULONG
            ProcessImagesHotPatched*    {.bitsize:1.}:  ULONG
            ReservedBits0*              {.bitsize:24.}: ULONG
        elif OsVer >= OS_10_Redstone2:
            ProcessPreviouslyThrottled* {.bitsize:1.}:  ULONG
            ProcessCurrentlyThrottled*  {.bitsize:1.}:  ULONG
            ReservedBits0*              {.bitsize:25.}: ULONG
        elif OsVer >= OS_8_1_2012R2RTM:
            ReservedBits0*              {.bitsize:27.}: ULONG

    PEB_LEAP_SECOND_FLAGS* {.pure, union.} = object
        SixtySecondEnabled* {.bitsize:1.}:  ULONG
        Reserved*           {.bitsize:31.}: ULONG

    PEB_TRACING_FLAGS* {.pure, union.} = object
        HeapTracingEnabled*         {.bitsize:1.}:  ULONG
        CritSecTracingEnabled*      {.bitsize:1.}:  ULONG
        LibLoaderTracingEnabled*    {.bitsize:1.}:  ULONG
        SpareTracingBits*           {.bitsize:29.}: ULONG

    PEB_UNION_1* {.pure, union.} = object
        KernelCallbackTable*:    PVOID
        UserSharedInfoPtr*:      PVOID

    PEB_LDR_DATA* {.pure.} = object
        Length*:                            ULONG
        Initialized*:                       BOOLEAN
        SsHandle*:                          PVOID
        InLoadOrderModuleList*:             LIST_ENTRY
        InMemoryOrderModuleList*:           LIST_ENTRY
        InInitializationOrderModuleList*:   LIST_ENTRY
        EntryInProgress*:                   PVOID
        ShutdownInProgress*:                BOOLEAN
        ShutdownThreadId*:                  HANDLE
    PPEB_LDR_DATA* = ptr PEB_LDR_DATA

    PEB* {.pure.} = object
        InheritedAddressSpace*:                 BOOLEAN
        ReadImageFileExecOptions*:              BOOLEAN
        BeingDebugged*:                         BOOLEAN
        Bitfield*:                              PEB_BITFIELD
        when OsVer >= OS_8_1_2012R2RTM:
            Padding0*:                          array[4, UCHAR]
        Mutant*:                                PVOID
        ImageBaseAddress*:                      PVOID
        Ldr*:                                   PPEB_LDR_DATA                             
        ProcessParameters*:                     PRTL_USER_PROCESS_PARAMETERS  
        SubSystemData*:                         PVOID                         
        ProcessHeap*:                           PVOID                        
        FastPebLock*:                           PRTL_CRITICAL_SECTION
        AtlThunkSListPtr*:                      PVOID           # union _SLIST_HEADER* volatile             
        IFEOKey*:                               PVOID                         
        CrossProcessFlags*:                     PEB_CROSSPROCESSFLAGS                         
        when OsVer >= OS_8_1_2012R2RTM:
            Padding1*:                          array[4, UCHAR]               
        KernelCallBackTableUnion*:              PEB_UNION_1                  
        SystemReserved*:                        ULONG                         
        AltThunkSListPtr32*:                    ULONG                         
        ApiSetMap*:                             PAPI_SET_NAMESPACE                         
        TlsExpansionCounter*:                   ULONG                         
        Padding2*:                              array[4, UCHAR]               
        TlsBitmap*:                             PVOID               # _RTL_BITMAP*          
        TlsBitmapBits*:                         array[2, ULONG]               
        ReadOnlyShareMemoryBase*:               PVOID                         
        SharedData*:                            PVOID                         
        ReadOnlyStaticServerData*:              ptr PVOID                     
        AnsiCodePageData*:                      PVOID                         
        OemCodePageData*:                       PVOID                         
        UnicodeCaseTableData*:                  PVOID                         
        NumberOfProcessors*:                    ULONG                         
        NtGlobalFlag*:                          ULONG                         
        CriticalSectionTimeout*:                LARGE_INTEGER                 
        HeapSegmentReserve*:                    ULONGLONG                     
        HeapSegmentCommit*:                     ULONGLONG                     
        HeapDeCommitTotalFreeThreshold*:        ULONGLONG                     
        HeapDeCommitFreeBlockThreshold*:        ULONGLONG                     
        NumberOfHeaps*:                         ULONG                         
        MaximumNumberOfHeaps*:                  ULONG                         
        ProcessHeaps*:                          ptr PVOID                     
        GdiSharedHandleTable*:                  PVOID                         
        ProcessStarterHelper*:                  PVOID                         
        GdiDCAttributeList*:                    ULONG                         
        when OsVer >= OS_8_1_2012R2RTM:
            Padding3*:                          array[4, UCHAR]               
        LoaderLock*:                            PRTL_CRITICAL_SECTION
        OSMajorVersion*:                        ULONG
        OSMinorVersion*:                        ULONG
        OSBuildNumber*:                         USHORT
        OSCSDVersion*:                          USHORT
        OSPlatformId*:                          ULONG
        ImageSubsystem*:                        ULONG
        ImageSubsystemMajorVersion*:            ULONG
        ImageSubsystemMinorVersion*:            ULONG
        when OsVer >= OS_8_1_2012R2RTM:
            Padding4*:                          array[4, UCHAR]
        ActiveProcessAffinityMask*:             ULONGLONG            # KAFFINITY
        GdiHandleBuffer*:                       array[0x3c, ULONG]
        PostProcessInitRoutine*:                VOID                    # VOID (*PostProcessInitRoutine)();  TODO
        TlsExpansionBitmap*:                    PVOID           # _RTL_BITMAP*
        TlsExpansionBitmapBits*:                array[0x20, ULONG]
        SessionId*:                             ULONG
        when OsVer >= OS_8_1_2012R2RTM:
            Padding5*:                          array[4, UCHAR]
        AppCompatFlags*:                        ULARGE_INTEGER
        AppCompatFlagsUser*:                    ULARGE_INTEGER
        ShimData*:                              PVOID
        AppCompatInfo*:                         PVOID
        CSDVersion*:                            UNICODE_STRING
        ActivationContextData*:                 PVOID             # PACTIVATION_CONTEXT_DATA 
        ProcessAssemblyStorageMap*:             PVOID             # PASSEMBLY_STORAGE_MAP
        SystemDefaultActivationContextData*:    PVOID             # PACTIVATION_CONTEXT_DATA
        SystemAssemblyStorageMap*:              PVOID             # PASSEMBLY_STORAGE_MAP
        MinimumStackCommit*:                    ULONGLONG
        
        when OsVer >= OS_11_InsiderPreview:
            Sparepointers*:                     array[2, PVOID]
            PatchLoaderData*:                   PVOID
            ChpeV2ProcessInfo*:                 PVOID               # _CHPEV2_PROCESS_INFO*
            when OsVer >= OS_11_21H2:
                AppModelFeatureState*:          ULONG
                SpareUlongs*:                   array[2, ULONG]
            elif OSVer == OS_11_InsiderPreview:
                SpareULongs*:                   array[3, ULONG]
            ActiveCodePage*:                    USHORT
            OemCodePage*:                       USHORT
            UseCaseMapping*:                    USHORT
            UnusedNlsField*:                    USHORT
        
        elif OsVer >= OS_10_19H1:
            Sparepointers*:                     array[4, PVOID]
            SpareULongs*:                       array[5, ULONG]

        else:
            FlsCallback*:                       PVOID   #FLS_CALLBACK_INFO*
            FlsListHead*:                       LIST_ENTRY
            FlsBitMap*:                         PVOID
            FlsBitMapBits*:                     array[4, ULONG]
            FlsHighIndex*:                      ULONG

        WerRegistrationData*:                   PVOID
        WerShipAssertPtr*:                      PVOID
        EcCodeBitMap*:                          PVOID
        ImageHeaderHash*:                       PVOID
        TracingFlags*:                          PEB_TRACING_FLAGS
        Padding6*:                              array[4, UCHAR]
        CsrServerReadOnlySharedMemoryBase*:     ULONGLONG
        
        when OsVer >= OS_10_Threshold2:
            TppWorkerpListLock*:                    ULONGLONG
            TppWorkerpList*:                        LIST_ENTRY
            WaitOnAddressHashTable*:                array[0x80, PVOID]
            
            when OsVer >= OS_10_Redstone3:
                TelemtryCoverageHeader*:                PVOID
                CloudFileFlags*:                        ULONG
                when OsVer >= OS_10_Redstone4:
                    CloudFileDiagFlags*:                ULONG
                    PlaceholderCompatabilityMode*:      CHAR
                    PlaceholderCompatabilityModeReserved*: array[7, CHAR]
                
                    when OsVer >= OS_10_Redstone5:
                        LeapSecondData*:                PVOID           #PLEAP_SECOND_DATA
                        LeapSecondFlags*:               PEB_LEAP_SECOND_FLAGS
                        NtGlobalFlag2*:                 ULONG
                        when OsVer >= OS_11_InsiderPreview:
                            ExtendedFeatureDisableMask*: ULONGLONG

    PPEB* = ptr PEB

## TEB
##-----------------------------------------------
type
    RTL_ACTIVATION_CONTEXT_STACK_FRAME* {.pure.} = object
        Previous*:          ptr RTL_ACTIVATION_CONTEXT_STACK_FRAME
        ActivationContext*: ptr ACTIVATION_CONTEXT
        Flags*:             ULONG
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME* = ptr RTL_ACTIVATION_CONTEXT_STACK_FRAME

    ACTIVATION_CONTEXT_STACK* {.pure.} = object
        ActiveFrame*:               PRTL_ACTIVATION_CONTEXT_STACK_FRAME
        FrameListCache*:            LIST_ENTRY
        Flags*:                     ULONG
        NextCookieSequenceNumber*:  ULONG
        StackId*:                   ULONG
    PACTIVATION_CONTEXT_STACK* = ptr ACTIVATION_CONTEXT_STACK

    GDI_TEB_BATCH* {.pure.} = object
        Offset*                 {.bitsize:31.}: ULONG
        HasRenderingCommand*    {.bitsize:1.}: ULONG
        HDC*:                   ULONGLONG
        Buffer*:                array[0x136, ULONG]

    TEB_ACTIVE_FRAME_CONTEXT* {.pure.} = object
        Flags*:     ULONG
        FrameName*: PCHAR
    PTEB_ACTIVE_FRAME_CONTEXT* = ptr TEB_ACTIVE_FRAME_CONTEXT

    TEB_ACTIVE_FRAME* {.pure.} = object
        Flags*:     ULONG
        Previous*:  ptr TEB_ACTIVE_FRAME
        Context*:   PTEB_ACTIVE_FRAME_CONTEXT
    PTEB_ACTIVE_FRAME* = ptr TEB_ACTIVE_FRAME

    TEB_PROCESSOR_STRUCT* {.pure.} = object
        ReservedPad0*:      UCHAR
        ReservedPad1*:      UCHAR
        ReservedPad2*:      UCHAR
        IdealProcessor*:    UCHAR

    TEB_PROCESSOR_UNION* {.pure, union.} = object
        CurrentIdealProcessor*: PROCESSOR_NUMBER
        IdealProcessorValue*:   ULONG
        IdealProcessorObj*:     TEB_PROCESSOR_STRUCT

    TEB_CROSSTEB_UNION* {.pure, union.} = object
        CrossTebFlags:                      USHORT
        SpareCrossTebBits {.bitsize:16.}:   USHORT

    TEB_SAMETEB_OBJ* {.pure.} = object
        SafeThunkCall*          {.bitsize:1.}: USHORT
        InDebugPrint*           {.bitsize:1.}: USHORT
        HasFiberData*           {.bitsize:1.}: USHORT
        SkipThreadAttach        {.bitsize:1.}: USHORT
        WerInShipAssertCode*    {.bitsize:1.}: USHORT
        RanProcessInit*         {.bitsize:1.}: USHORT
        ClonedThread*           {.bitsize:1.}: USHORT
        SuppressDebugMsg*       {.bitsize:1.}: USHORT
        DisableUserStackWalk*   {.bitsize:1.}: USHORT
        RtlExceptionAttached*   {.bitsize:1.}: USHORT
        InitialThread*          {.bitsize:1.}: USHORT
        SessionAware*           {.bitsize:1.}: USHORT
        LoadOwner*              {.bitsize:1.}: USHORT
        LoaderWorker*           {.bitsize:1.}: USHORT
        SkipLoaderInit*         {.bitsize:1.}: USHORT
        SkipFileAPIBrokering*   {.bitsize:1.}: USHORT

    TEB_SAMETEB_UNION* {.pure, union.} = object
        SameTebFlags*:  USHORT
        SameTebStruct*: TEB_SAMETEB_OBJ

    EXCEPTION_REGISTRATION_RECORD* {.pure.} = object
        Next*:      PEXCEPTION_REGISTRATION_RECORD
        Handler*:   PEXCEPTION_ROUTINE
    PEXCEPTION_REGISTRATION_RECORD* = ptr EXCEPTION_REGISTRATION_RECORD
    
    NT_TIB_UNION1* {.pure, union.} = object
        FiberData*: PVOID
        Version*:   DWORD
    NT_TIB* {.pure.} = object
        ExceptionList*:         PEXCEPTION_REGISTRATION_RECORD
        StackBase*:             PVOID
        StackLimit*:            PVOID
        SubSystemTib*:          PVOID
        Union1*:                NT_TIB_UNION1
        ArbitraryUserPointer*:  PVOID
        Self*:                  ptr NT_TIB
    PNT_TIB* = ptr NT_TIB
    
    TEB* {.pure.} = object
        NtTib*:                                 NT_TIB
        EnvironmentPointer*:                    PVOID
        ClientId*:                              CLIENT_ID
        ActiveRpcHandle*:                       PVOID
        ThreadLocalStoragePointer*:             PVOID
        ProcessEnvironmentBlock*:               PPEB
        LastErrorValue*:                        ULONG
        CountOfOwnedCriticalSections*:          ULONG
        CsrClientThread*:                       PVOID
        Win32ThreadInfo*:                       PVOID
        User32Reserved*:                        array[0x1A, ULONG]
        UserReserved*:                          array[5, ULONG]
        WOW32Reserved*:                         PVOID
        CurrentLocale*:                         ULONG
        FpSoftwareStatusRegister*:              ULONG
        ReservedForDebuggerInstrumentation*:    array[0x10, PVOID]
        SystemReserved1*:                       array[0x1E, PVOID]
        PlaceholderCompatibilityMode*:          CHAR
        PlaceholderHydrationAlwaysExplicit*:    UCHAR
        PlaceholderReserved*:                   array[0x0A, CHAR]
        ProxiedProcessId*:                      ULONG
        ActivationStack*:                       ACTIVATION_CONTEXT_STACK
        WorkingOnBehalfTicket*:                 array[0x08, UCHAR]
        ExceptionCode*:                         LONG
        Padding0*:                              array[0x04, UCHAR]
        ActivationContextStackPointer*:         PACTIVATION_CONTEXT_STACK
        InstrumentationCallbackSp*:             ULONGLONG
        InstrumentationCallbackPreviousPc*:     ULONGLONG
        InstrumentationCallbackPreviousSp*:     ULONGLONG
        TxFsContext*:                           ULONG
        InstrumentationCallbackDisabled*:       UCHAR
        UnalignedLoadStoreExceptions*:          UCHAR
        Padding1*:                              array[0x02, UCHAR]
        GdiTebBatch*:                           GDI_TEB_BATCH
        RealClientId*:                          CLIENT_ID
        GdiCachedProcessHandle*:                PVOID
        GdiClientPID*:                          ULONG
        GdiClientTID*:                          ULONG
        GdiThreadLocalInfo*:                    PVOID
        Win32ClientInfo*:                       array[0x3E, ULONGLONG]
        GlDispatchTable*:                       array[0xE9, PVOID]
        GlReserved1*:                           array[0x1D, ULONGLONG]
        GlReserved2*:                           PVOID
        GlSectionInfo*:                         PVOID
        GlSection*:                             PVOID
        GlTable*:                               PVOID
        GlCurrentRC*:                           PVOID
        GlContext*:                             PVOID
        LastStatusValue*:                       ULONG
        Padding2*:                              array[0x04, UCHAR]
        StaticUnicodeString*:                   UNICODE_STRING
        StaticUnicodeBuffer*:                   array[0x0105, WCHAR]
        Padding3*:                              array[0x06, UCHAR]
        DeallocationStack*:                     PVOID
        TlsSlots*:                              array[0x40, PVOID]
        TlsLinks*:                              LIST_ENTRY
        Vdm*:                                   PVOID
        ReservedForNtRpc*:                      PVOID
        DbgSsReserved*:                         array[0x02, PVOID]
        HardErrorMode*:                         ULONG
        Padding4*:                              array[0x04, UCHAR]
        Instrumentation*:                       array[0x0B, PVOID]
        ActivityId*:                            GUID
        SubProcessTag*:                         PVOID
        PerflibData*:                           PVOID
        EtwTraceData*:                          PVOID
        WinSockData*:                           PVOID
        GdiBatchCount*:                         ULONG
        Union1*:                                TEB_PROCESSOR_UNION
        GuaranteedStackBytes*:                  ULONG
        Padding5*:                              array[0x04, UCHAR]
        ReservedForPerf*:                       PVOID
        ReservedForOle*:                        PVOID
        WaitingOnLoaderLock*:                   ULONG
        Padding6*:                              array[0x04, UCHAR]
        SavedPriorityState*:                    PVOID
        ReservedForCodeCoverage*:               ULONGLONG
        ThreadPoolData*:                        PVOID
        TlsExpansionSlots*:                     ptr PVOID
        ChpeV2CpuAreaInfo*:                     PVOID
        Unused*:                                PVOID
        MuiGeneration*:                         ULONG
        IsImpersonating*:                       ULONG
        NlsCache*:                              PVOID
        PShimData*:                             PVOID
        HeapData*:                              ULONG
        Padding7*:                              array[0x04, UCHAR]
        CurrentTransactionHandle*:              PVOID
        ActiveFrame*:                           PTEB_ACTIVE_FRAME
        FlsData*:                               PVOID
        PreferredLanguages*:                    PVOID
        UserPrefLanguages*:                     PVOID
        MergedPrefLanguages*:                   PVOID
        MuiImpersonation*:                      ULONG
        Union2*:                                TEB_CROSSTEB_UNION
        Union3*:                                TEB_SAMETEB_UNION
        TxnScopeEnterCallback*:                 PVOID
        TxnScopeExitCallback*:                  PVOID
        TxnScopeContext*:                       PVOID
        LockCount*:                             ULONG
        WowTebOffset*:                          LONG
        ResourceRetValue*:                      PVOID
        ReservedForWdf*:                        PVOID
        ReservedForCrt*:                        ULONGLONG
        EffectiveContainerId*:                  GUID
        LastSleepCounter*:                      ULONGLONG
        SpinCallCount*:                         ULONG
        Padding8*:                              array[0x04, UCHAR]
        ExtendedFeatureDisableMask*:            ULONGLONG
    PTEB* = ptr TEB
