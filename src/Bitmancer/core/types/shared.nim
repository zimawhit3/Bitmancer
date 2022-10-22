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

## KSYSTEM_TIME
##-----------------------------------------------
type
    KSYSTEM_TIME* {.pure.} = object
        LowPart*:   ULONG
        High1Time*: LONG
        High2Time*: LONG

## KUSER_SHARED_DATA
##-----------------------------------------------
type
    ALTERNATIVE_ARCHITECTURE_TYPE* {.pure.} = enum
        StandardDesign,
        NEC98x86,
        EndAlternatives

    KUSER_SHARED_DATA_UNION_1_STRUCT* {.pure.} = object
        NXSupportPolicy*                {.bitsize: 2.}: UCHAR
        SEHValidationPolicy*            {.bitsize: 2.}: UCHAR
        CurDirDevicesSkippedForDlls*    {.bitsize: 2.}: UCHAR
        Reserved*                       {.bitsize: 2.}: UCHAR

    KUSER_SHARED_DATA_UNION_1* {.pure, union.} = object
        MitigationPolicies*:    UCHAR
        Struct1*:               KUSER_SHARED_DATA_UNION_1_STRUCT

    KUSER_SHARED_DATA_UNION_2_STRUCT* {.pure.} = object
        DbgErrorPortPresent*        {.bitsize: 1.}: ULONG
        DbgElevationEnabled*        {.bitsize: 1.}: ULONG
        DbgVirtEnabled*             {.bitsize: 1.}: ULONG
        DbgInstallerDetectEnabled*  {.bitsize: 1.}: ULONG
        DbgLkgEnabled*              {.bitsize: 1.}: ULONG
        DbgDynProcessorEnabled*     {.bitsize: 1.}: ULONG
        DbgConsoleBrokerEnabled*    {.bitsize: 1.}: ULONG
        DbgSecureBootEnabled*       {.bitsize: 1.}: ULONG
        DbgMultiSessionSku*         {.bitsize: 1.}: ULONG
        DbgMultiUsersInSessionSku*  {.bitsize: 1.}: ULONG
        DbgStateSeparationEnabled*  {.bitsize: 1.}: ULONG
        SpareBits*                  {.bitsize: 21.}: ULONG

    KUSER_SHARED_DATA_UNION_2* {.pure, union.} = object
        SharedDataFlags*:   ULONG
        Struct1*:           KUSER_SHARED_DATA_UNION_2_STRUCT

    KUSER_SHARED_DATA_TICK_COUNT* {.pure, union.} = object
        TickCount*:                 KSYSTEM_TIME
        TickCountQuad*:             ULONGLONG
        ReservedTickCountOverlay*:  array[3, ULONG]

    KUSER_SHARED_DATA* {.pure.} = object
        TickCountLowDeprecated*:        ULONG
        TickCountMultiplier*:           ULONG
        InterruptTime*:                 KSYSTEM_TIME
        SystemTime*:                    KSYSTEM_TIME
        TimeZoneBias*:                  KSYSTEM_TIME
        ImageNumberLow*:                USHORT
        ImageNumberHigh*:               USHORT
        NtSystemRoot*:                  array[260, WCHAR]
        MaxStackTraceDepth*:            ULONG
        CryptoExponent*:                ULONG
        TimeZoneId*:                    ULONG
        LargePageMinimum*:              ULONG
        AitSamplingValue*:              ULONG
        AppCompatFlag*:                 ULONG
        RNGSeedVersion*:                ULONGLONG
        GlobalValidationRunlevel*:      ULONG
        TimeZoneBiasStamp*:             ULONG
        NtBuildNumber*:                 ULONG
        NtProductType*:                 NT_PRODUCT_TYPE
        ProductTypeIsValid*:            UCHAR
        Reserved0*:                     UCHAR
        NativeProcessorArchitecture*:   USHORT
        NtMajorVersion*:                ULONG
        NtMinorVersion*:                ULONG
        ProcessorFeatures*:             array[64, UCHAR]
        Reserved1*:                     ULONG
        Reserved3*:                     ULONG
        TimeSlip*:                      ULONG
        AlternativeArchitecture*:       ALTERNATIVE_ARCHITECTURE_TYPE
        BootId*:                        ULONG
        SystemExpirationDate*:          LARGE_INTEGER
        SuiteMask*:                     ULONG
        KdDebuggerEnabled*:             UCHAR
        Union1*:                        KUSER_SHARED_DATA_UNION_1
        CyclesPerYield*:                USHORT
        ActiveConsoleId*:               ULONG
        DismountCount*:                 ULONG
        ComPlusPackage*:                ULONG
        LastSystemRITEventTickCount*:   ULONG
        NumberOfPhysicalPages*:         ULONG
        SafeBootMode*:                  UCHAR
        VirtualizationFlags*:           UCHAR
        Reserved12*:                    array[2, UCHAR]
        Union2*:                        KUSER_SHARED_DATA_UNION_2
        DataFlagsPad*:                  ULONG
        TestRetInstruction*:            ULONGLONG
        QpcFrequency*:                  LONGLONG
        SystemCall*:                    ULONG
        Reserved2*:                     ULONG
        SystemCallPad*:                 array[2, ULONGLONG]
        Union3*:                        KUSER_SHARED_DATA_TICK_COUNT
        TickCountPad*:                  ULONG
        Cookie*:                        ULONG
        CookiePad*:                     ULONG
        ConsoleSessionForegroundProcessId*: LONGLONG
        TimeUpdateLock*:                ULONGLONG
        BaselineSystemTimeQpc*:         ULONGLONG
        BaselineInterruptTimeQpc*:      ULONGLONG
        QpcSystemTimeIncrement*:        ULONGLONG
        QpcInterruptTimeIncrement*:     ULONGLONG
        QpcSystemTimeIncrementShift*:   UCHAR
        QpcInterruptTimeIncrementShift*:    UCHAR
        UnparkedProcessorCount*:        USHORT
        EnclaveFeatureMask*:            array[4, ULONG]
        TelemetryCoverageRound*:        ULONG
        UserModeGlobalLogger*:          array[16, USHORT]
        ImageFileExecutionOptions*:     ULONG
        LangGenerationCount*:           ULONG
        Reserved4*:                     ULONGLONG
        InterruptTimeBias*:             ULONGLONG
        QpcBias*:                       ULONGLONG
        ActiveProcessorCount*:          ULONG
        ActiveGroupCount*:              UCHAR
        Reserved9*:                     UCHAR
        QpcData*:                       USHORT
        TimeZoneBiasEffectiveStart*:    LARGE_INTEGER
        TimeZoneBiasEffectiveEnd*:      LARGE_INTEGER
        XState*:                        XSTATE_CONFIGURATION
        FeatureConfigurationChangeStamp*: KSYSTEM_TIME
        Spare*:                         ULONG

    PKUSER_SHARED_DATA* = ptr KUSER_SHARED_DATA
