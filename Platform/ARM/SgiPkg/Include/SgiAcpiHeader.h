/** @file
*
*  Copyright (c) 2018-2022, ARM Limited. All rights reserved.
*
*  SPDX-License-Identifier: BSD-2-Clause-Patent
*
**/

#ifndef __SGI_ACPI_HEADER__
#define __SGI_ACPI_HEADER__

#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/IoRemappingTable.h>

//
// ACPI table information used to initialize tables.
//
#define EFI_ACPI_ARM_OEM_ID           'A','R','M','L','T','D'   // OEMID 6 bytes long
#define EFI_ACPI_ARM_OEM_TABLE_ID     SIGNATURE_64 ('A','R','M','S','G','I',' ',' ') // OEM table id 8 bytes long
#define EFI_ACPI_ARM_OEM_REVISION     0x20140727
#define EFI_ACPI_ARM_CREATOR_ID       SIGNATURE_32('A','R','M',' ')
#define EFI_ACPI_ARM_CREATOR_REVISION 0x00000099

#define CORE_COUNT      FixedPcdGet32 (PcdCoreCount)
#define CLUSTER_COUNT   FixedPcdGet32 (PcdClusterCount)

// ACPI OSC Status bits
#define OSC_STS_BIT0_RES              (1U << 0)
#define OSC_STS_FAILURE               (1U << 1)
#define OSC_STS_UNRECOGNIZED_UUID     (1U << 2)
#define OSC_STS_UNRECOGNIZED_REV      (1U << 3)
#define OSC_STS_CAPABILITY_MASKED     (1U << 4)
#define OSC_STS_MASK                  (OSC_STS_BIT0_RES          | \
                                       OSC_STS_FAILURE           | \
                                       OSC_STS_UNRECOGNIZED_UUID | \
                                       OSC_STS_UNRECOGNIZED_REV  | \
                                       OSC_STS_CAPABILITY_MASKED)

// ACPI OSC for Platform-Wide Capability
#define OSC_CAP_CPPC_SUPPORT          (1U << 5)
#define OSC_CAP_CPPC2_SUPPORT         (1U << 6)
#define OSC_CAP_PLAT_COORDINATED_LPI  (1U << 7)
#define OSC_CAP_OS_INITIATED_LPI      (1U << 8)

#pragma pack(1)
// PPTT processor core structure
typedef struct {
  EFI_ACPI_6_3_PPTT_STRUCTURE_PROCESSOR  Core;
  UINT32                                 ResourceOffset[2];
  EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE      DCache;
  EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE      ICache;
  EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE      L2Cache;
} RD_PPTT_CORE;

// PPTT processor cluster structure
typedef struct {
  EFI_ACPI_6_3_PPTT_STRUCTURE_PROCESSOR  Cluster;
  UINT32                                 ResourceOffset;
  EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE      L3Cache;
  RD_PPTT_CORE                           Core[CORE_COUNT];
} RD_PPTT_CLUSTER;

// PPTT processor cluster structure without cache
typedef struct {
  EFI_ACPI_6_3_PPTT_STRUCTURE_PROCESSOR  Cluster;
  RD_PPTT_CORE                           Core[CORE_COUNT];
} RD_PPTT_MINIMAL_CLUSTER;

// PPTT processor package structure
typedef struct {
  EFI_ACPI_6_3_PPTT_STRUCTURE_PROCESSOR  Package;
  UINT32                                 ResourceOffset;
  EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE      Slc;
  RD_PPTT_MINIMAL_CLUSTER                Cluster[CLUSTER_COUNT];
} RD_PPTT_SLC_PACKAGE;
#pragma pack ()

//
// PPTT processor structure flags for different SoC components as defined in
// ACPI 6.3 specification
//

// Processor structure flags for SoC package
#define PPTT_PROCESSOR_PACKAGE_FLAGS                                           \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_PACKAGE_PHYSICAL,                                        \
    EFI_ACPI_6_3_PPTT_PROCESSOR_ID_INVALID,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_IS_NOT_THREAD,                                 \
    EFI_ACPI_6_3_PPTT_NODE_IS_NOT_LEAF,                                        \
    EFI_ACPI_6_3_PPTT_IMPLEMENTATION_IDENTICAL                                 \
  }

// Processor structure flags for cluster
#define PPTT_PROCESSOR_CLUSTER_FLAGS                                           \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_PACKAGE_NOT_PHYSICAL,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_ID_VALID,                                      \
    EFI_ACPI_6_3_PPTT_PROCESSOR_IS_NOT_THREAD,                                 \
    EFI_ACPI_6_3_PPTT_NODE_IS_NOT_LEAF,                                        \
    EFI_ACPI_6_3_PPTT_IMPLEMENTATION_IDENTICAL                                 \
  }

// Processor structure flags for cluster with multi-thread core
#define PPTT_PROCESSOR_CLUSTER_THREADED_FLAGS                                  \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_PACKAGE_NOT_PHYSICAL,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_ID_INVALID,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_IS_NOT_THREAD,                                 \
    EFI_ACPI_6_3_PPTT_NODE_IS_NOT_LEAF,                                        \
    EFI_ACPI_6_3_PPTT_IMPLEMENTATION_IDENTICAL                                 \
  }

// Processor structure flags for single-thread core
#define PPTT_PROCESSOR_CORE_FLAGS                                              \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_PACKAGE_NOT_PHYSICAL,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_ID_VALID,                                      \
    EFI_ACPI_6_3_PPTT_PROCESSOR_IS_NOT_THREAD,                                 \
    EFI_ACPI_6_3_PPTT_NODE_IS_LEAF                                             \
  }

// Processor structure flags for multi-thread core
#define PPTT_PROCESSOR_CORE_THREADED_FLAGS                                     \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_PACKAGE_NOT_PHYSICAL,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_ID_INVALID,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_IS_NOT_THREAD,                                 \
    EFI_ACPI_6_3_PPTT_NODE_IS_NOT_LEAF,                                        \
    EFI_ACPI_6_3_PPTT_IMPLEMENTATION_IDENTICAL                                 \
  }

// Processor structure flags for CPU thread
#define PPTT_PROCESSOR_THREAD_FLAGS                                            \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_PACKAGE_NOT_PHYSICAL,                                    \
    EFI_ACPI_6_3_PPTT_PROCESSOR_ID_VALID,                                      \
    EFI_ACPI_6_3_PPTT_PROCESSOR_IS_THREAD,                                     \
    EFI_ACPI_6_3_PPTT_NODE_IS_LEAF                                             \
  }

// PPTT cache structure flags as defined in ACPI 6.3 Specification
#define PPTT_CACHE_STRUCTURE_FLAGS                                             \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_CACHE_SIZE_VALID,                                        \
    EFI_ACPI_6_3_PPTT_NUMBER_OF_SETS_VALID,                                    \
    EFI_ACPI_6_3_PPTT_ASSOCIATIVITY_VALID,                                     \
    EFI_ACPI_6_3_PPTT_ALLOCATION_TYPE_VALID,                                   \
    EFI_ACPI_6_3_PPTT_CACHE_TYPE_VALID,                                        \
    EFI_ACPI_6_3_PPTT_WRITE_POLICY_VALID,                                      \
    EFI_ACPI_6_3_PPTT_LINE_SIZE_VALID                                          \
  }

// PPTT cache attributes for data cache
#define PPTT_DATA_CACHE_ATTR                                                   \
  {                                                                            \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_ALLOCATION_READ_WRITE,                       \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_CACHE_TYPE_DATA,                             \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_WRITE_POLICY_WRITE_BACK                      \
  }

// PPTT cache attributes for instruction cache
#define PPTT_INST_CACHE_ATTR                                                   \
  {                                                                            \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_ALLOCATION_READ,                             \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_CACHE_TYPE_INSTRUCTION,                      \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_WRITE_POLICY_WRITE_BACK                      \
  }

// PPTT cache attributes for unified cache
#define PPTT_UNIFIED_CACHE_ATTR                                                \
  {                                                                            \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_ALLOCATION_READ_WRITE,                       \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_CACHE_TYPE_UNIFIED,                          \
    EFI_ACPI_6_3_CACHE_ATTRIBUTES_WRITE_POLICY_WRITE_BACK                      \
  }

// A macro to initialise the common header part of EFI ACPI tables as defined by
// EFI_ACPI_DESCRIPTION_HEADER structure.
#define ARM_ACPI_HEADER(Signature, Type, Revision) {             \
    Signature,                      /* UINT32  Signature */       \
    sizeof (Type),                  /* UINT32  Length */          \
    Revision,                       /* UINT8   Revision */        \
    0,                              /* UINT8   Checksum */        \
    { EFI_ACPI_ARM_OEM_ID },        /* UINT8   OemId[6] */        \
    EFI_ACPI_ARM_OEM_TABLE_ID,      /* UINT64  OemTableId */      \
    EFI_ACPI_ARM_OEM_REVISION,      /* UINT32  OemRevision */     \
    EFI_ACPI_ARM_CREATOR_ID,        /* UINT32  CreatorId */       \
    EFI_ACPI_ARM_CREATOR_REVISION   /* UINT32  CreatorRevision */ \
  }

// EFI_ACPI_6_2_GIC_STRUCTURE
#define EFI_ACPI_6_2_GICC_STRUCTURE_INIT(GicId, AcpiCpuUid, Mpidr, Flags,      \
  PmuIrq, GicBase, GicVBase, GicHBase, GsivId, GicRBase, Efficiency)           \
  {                                                                            \
    EFI_ACPI_6_2_GIC,                     /* Type */                           \
    sizeof (EFI_ACPI_6_2_GIC_STRUCTURE),  /* Length */                         \
    EFI_ACPI_RESERVED_WORD,               /* Reserved */                       \
    GicId,                                /* CPUInterfaceNumber */             \
    AcpiCpuUid,                           /* AcpiProcessorUid */               \
    Flags,                                /* Flags */                          \
    0,                                    /* ParkingProtocolVersion */         \
    PmuIrq,                               /* PerformanceInterruptGsiv */       \
    0,                                    /* ParkedAddress */                  \
    GicBase,                              /* PhysicalBaseAddress */            \
    GicVBase,                             /* GICV */                           \
    GicHBase,                             /* GICH */                           \
    GsivId,                               /* VGICMaintenanceInterrupt */       \
    GicRBase,                             /* GICRBaseAddress */                \
    Mpidr,                                /* MPIDR */                          \
    Efficiency,                           /* ProcessorPowerEfficiencyClass */  \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,             /* Reserved2[0] */                   \
      EFI_ACPI_RESERVED_BYTE,             /* Reserved2[1] */                   \
      EFI_ACPI_RESERVED_BYTE              /* Reserved2[2] */                   \
    }                                                                          \
  }

// EFI_ACPI_6_2_GIC_DISTRIBUTOR_STRUCTURE
#define EFI_ACPI_6_2_GIC_DISTRIBUTOR_INIT(GicDistHwId, GicDistBase,            \
  GicDistVector, GicVersion)                                                   \
  {                                                                            \
    EFI_ACPI_6_2_GICD,                    /* Type */                           \
    sizeof (EFI_ACPI_6_2_GIC_DISTRIBUTOR_STRUCTURE),                           \
    EFI_ACPI_RESERVED_WORD,               /* Reserved1 */                      \
    GicDistHwId,                          /* GicId */                          \
    GicDistBase,                          /* PhysicalBaseAddress */            \
    GicDistVector,                        /* SystemVectorBase */               \
    GicVersion,                           /* GicVersion */                     \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,             /* Reserved2[0] */                   \
      EFI_ACPI_RESERVED_BYTE,             /* Reserved2[1] */                   \
      EFI_ACPI_RESERVED_BYTE              /* Reserved2[2] */                   \
    }                                                                          \
  }

// EFI_ACPI_6_2_GICR_STRUCTURE
#define EFI_ACPI_6_2_GIC_REDISTRIBUTOR_INIT(RedisRegionAddr, RedisDiscLength)  \
  {                                                                            \
    EFI_ACPI_6_2_GICR,                    /* Type */                           \
    sizeof (EFI_ACPI_6_2_GICR_STRUCTURE), /* Length */                         \
    EFI_ACPI_RESERVED_WORD,               /* Reserved */                       \
    RedisRegionAddr,                      /* DiscoveryRangeBaseAddress */      \
    RedisDiscLength                       /* DiscoveryRangeLength */           \
  }

// EFI_ACPI_6_2_GIC_ITS_STRUCTURE
#define EFI_ACPI_6_2_GIC_ITS_INIT(GicItsId, GicItsBase)                        \
  {                                                                            \
    EFI_ACPI_6_2_GIC_ITS,                 /* Type */                           \
    sizeof (EFI_ACPI_6_2_GIC_ITS_STRUCTURE),                                   \
    EFI_ACPI_RESERVED_WORD,               /* Reserved */                       \
    GicItsId,                             /* GicItsId */                       \
    GicItsBase,                           /* PhysicalBaseAddress */            \
    EFI_ACPI_RESERVED_DWORD               /* DiscoveryRangeLength */           \
  }

// EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE
#define EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE_INIT(                           \
          ProximityDomain, Base, Length, Flags)                                \
  {                                                                            \
    1, sizeof (EFI_ACPI_6_3_MEMORY_AFFINITY_STRUCTURE), ProximityDomain,       \
    EFI_ACPI_RESERVED_WORD, (Base) & 0xffffffff,                               \
    (Base) >> 32, (Length) & 0xffffffff,                                       \
    (Length) >> 32, EFI_ACPI_RESERVED_DWORD, Flags,                            \
    EFI_ACPI_RESERVED_QWORD                                                    \
  }

// EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE
#define EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE_INIT(                             \
          ProximityDomain, ACPIProcessorUID, Flags, ClockDomain)               \
  {                                                                            \
    3, sizeof (EFI_ACPI_6_3_GICC_AFFINITY_STRUCTURE), ProximityDomain,         \
    ACPIProcessorUID,  Flags,  ClockDomain                                     \
  }

//
// HMAT related structures
//
// Memory Proximity Domain Attributes Structure
// Refer Section 5.2.27.3 in ACPI Specification, Version 6.3
#define EFI_ACPI_6_3_HMAT_STRUCTURE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES_INIT(   \
    Flags, ProximityDomainForAttachedIntiator, ProximityDomainForMemory)       \
  {                                                                            \
    EFI_ACPI_6_3_HMAT_TYPE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES,                 \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE                                                   \
    },                                                                         \
    sizeof (EFI_ACPI_6_3_HMAT_STRUCTURE_MEMORY_PROXIMITY_DOMAIN_ATTRIBUTES),   \
    {                                                                          \
      Flags,                                                                   \
      0                                                                        \
    },                                                                         \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE                                                   \
    },                                                                         \
    ProximityDomainForAttachedIntiator,                                        \
    ProximityDomainForMemory,                                                  \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE                                                   \
    }                                                                          \
  }

// System Locality Latency and Bandwidth Information Structure
// Refer Section 5.2.27.4 in ACPI Specification, Version 6.3
#define EFI_ACPI_6_3_HMAT_STRUCTURE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO_INIT(  \
    Flags, DataType, NumInitiatorProximityDomains,                                    \
    NumTargetProximityDomains, EntryBaseUnit)                                         \
  {                                                                                   \
    EFI_ACPI_6_3_HMAT_TYPE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO,                \
    {                                                                                 \
      EFI_ACPI_RESERVED_BYTE,                                                         \
      EFI_ACPI_RESERVED_BYTE                                                          \
    },                                                                                \
    sizeof (EFI_ACPI_6_3_HMAT_STRUCTURE_SYSTEM_LOCALITY_LATENCY_AND_BANDWIDTH_INFO) + \
      (4 * NumInitiatorProximityDomains) + (4 * NumTargetProximityDomains) +          \
      (2 * NumInitiatorProximityDomains * NumTargetProximityDomains),                 \
    {                                                                                 \
      Flags,                                                                          \
      0                                                                               \
    },                                                                                \
    DataType,                                                                         \
    {                                                                                 \
      EFI_ACPI_RESERVED_BYTE,                                                         \
      EFI_ACPI_RESERVED_BYTE                                                          \
    },                                                                                \
    NumInitiatorProximityDomains,                                                     \
    NumTargetProximityDomains,                                                        \
    {                                                                                 \
      EFI_ACPI_RESERVED_BYTE,                                                         \
      EFI_ACPI_RESERVED_BYTE,                                                         \
      EFI_ACPI_RESERVED_BYTE,                                                         \
      EFI_ACPI_RESERVED_BYTE                                                          \
    },                                                                                \
    EntryBaseUnit                                                                     \
  }

// Memory Side Cache Information Structure
// Refer Section 5.2.27.5 in ACPI Specification, Version 6.3
#define EFI_ACPI_6_3_HMAT_STRUCTURE_MEMORY_SIDE_CACHE_INFO_INIT(               \
    MemoryProximityDomain, MemorySideCacheSize, CacheAttributes,               \
    NumberOfSmbiosHandles)                                                     \
  {                                                                            \
    EFI_ACPI_6_3_HMAT_TYPE_MEMORY_SIDE_CACHE_INFO,                             \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE                                                   \
    },                                                                         \
    sizeof (EFI_ACPI_6_3_HMAT_STRUCTURE_MEMORY_SIDE_CACHE_INFO) +              \
      (NumberOfSmbiosHandles * 2),                                             \
    MemoryProximityDomain,                                                     \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE                                                   \
    },                                                                         \
    MemorySideCacheSize,                                                       \
    CacheAttributes,                                                           \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE                                                   \
    },                                                                         \
    NumberOfSmbiosHandles                                                      \
  }

/** A macro to initialise the Memory Side Cache Information Attributes.
    See Table 5.124 in ACPI Specification, Version 6.3

  @param [in] TotalCacheLevels    Total Cache Levels for this Memory Proximity.
  @param [in] CacheLevel          Cache Level described in this structure.
  @param [in] CacheAssociativity  Cache Associativity.
  @param [in] WritePolicy         Write Policy.
  @param [in] CacheLineSize       Cache Line size in bytes.
**/
#define HMAT_STRUCTURE_MEMORY_SIDE_CACHE_INFO_CACHE_ATTRIBUTES_INIT(           \
  TotalCacheLevels, CacheLevel, CacheAssociativity, WritePolicy, CacheLineSize \
  )                                                                            \
{                                                                              \
  TotalCacheLevels, CacheLevel, CacheAssociativity, WritePolicy, CacheLineSize \
}

// EFI_ACPI_6_3_PPTT_STRUCTURE_PROCESSOR
#define EFI_ACPI_6_3_PPTT_STRUCTURE_PROCESSOR_INIT(Length, Flag, Parent,       \
  ACPIProcessorID, NumberOfPrivateResource)                                    \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_TYPE_PROCESSOR,                 /* Type 0 */             \
    Length,                                           /* Length */             \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
    },                                                                         \
    Flag,                                             /* Processor flags */    \
    Parent,                                           /* Ref to parent node */ \
    ACPIProcessorID,                                  /* UID, as per MADT */   \
    NumberOfPrivateResource                           /* Resource count */     \
  }

// EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE
#define EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE_INIT(Flag, NextLevelCache, Size,     \
  NoOfSets, Associativity, Attributes, LineSize)                               \
  {                                                                            \
    EFI_ACPI_6_3_PPTT_TYPE_CACHE,                     /* Type 1 */             \
    sizeof (EFI_ACPI_6_3_PPTT_STRUCTURE_CACHE),       /* Length */             \
    {                                                                          \
      EFI_ACPI_RESERVED_BYTE,                                                  \
      EFI_ACPI_RESERVED_BYTE,                                                  \
    },                                                                         \
    Flag,                                             /* Cache flags */        \
    NextLevelCache,                                   /* Ref to next level */  \
    Size,                                             /* Size in bytes */      \
    NoOfSets,                                         /* Num of sets */        \
    Associativity,                                    /* Num of ways */        \
    Attributes,                                       /* Cache attributes */   \
    LineSize                                          /* Line size in bytes */ \
  }

/** Helper macro for CPPC _CPC object initialization. Use of this macro is
    restricted to ASL file and not to TDL file.

    @param [in] DesiredPerfReg      Fastchannel address for desired performance
                                    register.
    @param [in] PerfLimitedReg      Fastchannel address for performance limited
                                    register.
    @param [in] GranularityMHz      Granularity of the performance scale.
    @param [in] HighestPerf         Highest performance in linear scale.
    @param [in] NominalPerf         Nominal performance in linear scale.
    @param [in] LowestNonlinearPerf Lowest non-linear performnce in linear
                                    scale.
    @param [in] LowestPerf          Lowest performance in linear scale.
    @param [in] RefPerf             Reference performance in linear scale.
**/
#define CPPC_PACKAGE_INIT(DesiredPerfReg, PerfLimitedReg, GranularityMHz,      \
  HighestPerf, NominalPerf, LowestNonlinearPerf, LowestPerf, RefPerf)          \
  {                                                                            \
    23,                                 /* NumEntries */                       \
    3,                                  /* Revision */                         \
    HighestPerf,                        /* Highest Performance */              \
    NominalPerf,                        /* Nominal Performance */              \
    LowestNonlinearPerf,                /* Lowest Nonlinear Performance */     \
    LowestPerf,                         /* Lowest Performance */               \
    /* Guaranteed Performance Register */                                      \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Desired Performance Register */                                         \
    ResourceTemplate () { Register (SystemMemory, 32, 0, DesiredPerfReg, 3) }, \
    /* Minimum Performance Register */                                         \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Maximum Performance Register */                                         \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Performance Reduction Tolerance Register */                             \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Time Window Register */                                                 \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Counter Wraparound Time */                                              \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Reference Performance Counter Register */                               \
    ResourceTemplate () { Register (FFixedHW, 64, 0, 1, 4) },                  \
    /* Delivered Performance Counter Register */                               \
    ResourceTemplate () { Register (FFixedHW, 64, 0, 0, 4) },                  \
    /* Performance Limited Register */                                         \
    ResourceTemplate () { Register (SystemMemory, 32, 0, PerfLimitedReg, 3) }, \
    /* CPPC Enable Register */                                                 \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Autonomous Selection Enable Register */                                 \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Autonomous Activity Window Register */                                  \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    /* Energy Performance Preference Register */                               \
    ResourceTemplate () { Register (SystemMemory, 0, 0, 0, 0) },               \
    RefPerf,                            /* Reference Performance */            \
    (LowestPerf * GranularityMHz),      /* Lowest Frequency */                 \
    (NominalPerf * GranularityMHz),     /* Nominal Frequency */                \
  }

// Power state dependancy (_PSD) for CPPC

/** Helper macro to initialize Power state dependancy (_PSD) object required
    for CPPC. Use of this macro is restricted to ASL file and not to TDL file.

    @param [in] Domain              The dependency domain number to which this
                                    P-state entry belongs.
**/
#define PSD_INIT(Domain)                                                       \
  {                                                                            \
    5,              /* Entries */                                              \
    0,              /* Revision */                                             \
    Domain,         /* Domain */                                               \
    0xFD,           /* Coord Type- SW_ANY */                                   \
    1               /* Processors */                                           \
  }

#pragma pack(1)
typedef struct
{
  EFI_ACPI_6_0_IO_REMAPPING_ITS_NODE       ItsNode;
  UINT32                                   ItsIdentifiers;
} ARM_EFI_ACPI_6_0_IO_REMAPPING_ITS_NODE;

typedef struct
{
  EFI_ACPI_6_0_IO_REMAPPING_SMMU3_NODE     SmmuNode;
  EFI_ACPI_6_0_IO_REMAPPING_ID_TABLE       SmmuIdMap[3];
} ARM_EFI_ACPI_6_0_IO_REMAPPING_SMMU3_NODE;

typedef struct
{
  EFI_ACPI_6_0_IO_REMAPPING_NAMED_COMP_NODE  DmaNode;
  CONST CHAR8                                Name[16];
  EFI_ACPI_6_0_IO_REMAPPING_ID_TABLE         DmaIdMap[9];
} ARM_EFI_ACPI_6_0_IO_REMAPPING_DMA_NC_NODE;
#pragma pack ()

/** Helper macro for ITS group node initialization for Arm Iort table.
    See Table 12 of Arm IORT specification, version E.b.

    @param [in] IoVirtBlkIdx      Index of IO virtualization block in which
                                  the ITS block is present.
**/
#define EFI_ACPI_ITS_INIT(IoVirtBlkIdx)                                        \
  /* ARM_EFI_ACPI_6_0_IO_REMAPPING_ITS_NODE */                                 \
  {                                                                            \
    /* EFI_ACPI_6_0_IO_REMAPPING_ITS_NODE */                                   \
    {                                                                          \
      /* EFI_ACPI_6_0_IO_REMAPPING_NODE */                                     \
      {                                                                        \
        EFI_ACPI_IORT_TYPE_ITS_GROUP,                     /* Type */           \
        sizeof (ARM_EFI_ACPI_6_0_IO_REMAPPING_ITS_NODE),  /* Length */         \
        1,                                                /* Revision */       \
        0,                                                /* Identifier */     \
        0,                                                /* NumIdMappings */  \
        0,                                                /* IdReference */    \
      },                                                                       \
      1,                                                  /* ITS count */      \
    },                                                                         \
    IoVirtBlkIdx,                                   /* GIC ITS Identifiers */  \
  }

/** Helper macro for ID mapping table initialization of SMMUv3 IORT node.
    See Table 4 of Arm IORT specification, version E.b.

    @param [in] BaseStreamId    Starting ID in the range of StreamIDs allowed
                                by SMMUv3. Since SMMUv3 doesn't offset input
                                IDs, so InputBase and OutputBase are identical.

    @param [in] NumIds          Number of StreamIDs in the StreamID range.
**/
#define EFI_ACPI_SMMUv3_ID_TABLE_INIT(BaseStreamId, NumIds)                    \
   {                                                                           \
     BaseStreamId,                             /* InputBase */                 \
     NumIds,                                   /* NumIds */                    \
     BaseStreamId,                             /* OutputBase */                \
     OFFSET_OF (ARM_EFI_ACPI_6_0_IO_REMAPPING_TABLE,                           \
       ItsNode),                               /* OutputReference */           \
     0,                                        /* Flags */                     \
   }

// StreamID base for PL330 DMA0 controller
#define DMA0_STREAM_ID_BASE                                                    \
          FixedPcdGet32 (PcdPciex41DevIDBase) +                                \
          FixedPcdGet32 (PcdIoVirtBlkDma0StreamIDBase)

// StreamID base for PL330 DMA1 controller
#define DMA1_STREAM_ID_BASE                                                    \
          FixedPcdGet32 (PcdPciex16DevIDBase) +                                \
          FixedPcdGet32 (PcdIoVirtBlkDma1StreamIDBase)

/** Helper macro for SMMUv3 node initialization for Arm Iort table.
    See Table 9 of Arm IORT specification, version E.b.

    @param [in] IoVirtBlkIdx      Index of IO virtualization block in which
                                  the SMMUv3 block is present.
**/
#define EFI_ACPI_SMMUv3_INIT(IoVirtBlkIdx)                                     \
  /* ARM_EFI_ACPI_6_0_IO_REMAPPING_SMMU3_NODE */                               \
  {                                                                            \
    /* EFI_ACPI_6_0_IO_REMAPPING_SMMU3_NODE */                                 \
    {                                                                          \
      /* EFI_ACPI_6_0_IO_REMAPPING_NODE */                                     \
      {                                                                        \
        EFI_ACPI_IORT_TYPE_SMMUv3,                          /* Type */         \
        sizeof (ARM_EFI_ACPI_6_0_IO_REMAPPING_SMMU3_NODE),  /* Length */       \
        4,                                                  /* Revision */     \
        0,                                                  /* Identifier */   \
        3,                                                  /* NumIdMapping */ \
        OFFSET_OF (ARM_EFI_ACPI_6_0_IO_REMAPPING_SMMU3_NODE,                   \
          SmmuIdMap),                                       /* IdReference */  \
      },                                                                       \
      (FixedPcdGet32 (PcdSmmuBase) + (0x2000000 * IoVirtBlkIdx)),              \
                                                      /* Base address */       \
      EFI_ACPI_IORT_SMMUv3_FLAG_COHAC_OVERRIDE,       /* Flags */              \
      0,                                              /* Reserved */           \
      0x0,                                            /* VATOS address */      \
      EFI_ACPI_IORT_SMMUv3_MODEL_GENERIC,             /* SMMUv3 Model */       \
      FixedPcdGet32 (PcdSmmuEventGsiv),               /* Event */              \
      FixedPcdGet32 (PcdSmmuPriGsiv),                 /* Pri */                \
      FixedPcdGet32 (PcdSmmuGErrorGsiv),              /* Gerror */             \
      FixedPcdGet32 (PcdSmmuSyncGsiv),                /* Sync */               \
      0,                                              /* Proximity domain */   \
      2,                                              /* DevIDMappingIndex */  \
    },                                                                         \
    /* EFI_ACPI_6_0_IO_REMAPPING_ID_TABLE */                                   \
    {                                                                          \
      EFI_ACPI_SMMUv3_ID_TABLE_INIT(DMA0_STREAM_ID_BASE,                       \
        (FixedPcdGet32 (PcdIoVirtBlkDma0NumCh) + 1)),                          \
      EFI_ACPI_SMMUv3_ID_TABLE_INIT(DMA1_STREAM_ID_BASE,                       \
        (FixedPcdGet32 (PcdIoVirtBlkDma1NumCh) + 1)),                          \
      {                                                                        \
        0x0,                                         /* InputBase */           \
        1,                                           /* NumIds */              \
        FixedPcdGet32 (PcdSmmuDevIDBase),            /* OutputBase */          \
        OFFSET_OF (ARM_EFI_ACPI_6_0_IO_REMAPPING_TABLE,                        \
          ItsNode),                                  /* OutputReference */     \
        EFI_ACPI_IORT_ID_MAPPING_FLAGS_SINGLE,       /* Flags */               \
      },                                                                       \
    },                                                                         \
  }

/** Helper macro for ID mapping table initialization of DMA Named Component
    IORT node.
    See Table 4 of Arm IORT specification, version E.b.
    Output StreamID for a channel can be calculated as -
    ((IDBase for x16/x8/x4_1/x4_0) + BaseSID of DMA controller) + Channel Idx).

    @param [in] DmaIdx           Index of DMA pl330 controller connected to
                                 a non-PCIe IO virtualization block.
    @param [in] ChStreamIdx      Channel index within one DMA controller -
                                 0 to 8.
**/
#define EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, ChStreamIdx)                     \
  {                                                                            \
    ChStreamIdx,                                    /* InputBase */            \
    1,                                              /* NumIds */               \
    DMA ##DmaIdx ## _STREAM_ID_BASE + ChStreamIdx,  /* OutputBase */           \
    OFFSET_OF (ARM_EFI_ACPI_6_0_IO_REMAPPING_TABLE,                            \
      SmmuNode),                                    /* OutputReference */      \
    EFI_ACPI_IORT_ID_MAPPING_FLAGS_SINGLE,          /* Flags */                \
  }

/** Helper macro for DMA Named Component node initialization for Arm Iort
    table.
    See Table 13 of Arm IORT specification, version E.b.

    @param [in] DmaIdx           Index of DMA pl330 controller connected to
                                 a non-PCIe IO virtualization block.

    @param [in] RefName          Device object name in the ACPI namespace.
**/
#define EFI_ACPI_DMA_NC_INIT(DmaIdx, RefName)                                  \
  /* ARM_EFI_ACPI_6_0_IO_REMAPPING_DMA_NC_NODE */                              \
  {                                                                            \
    /* EFI_ACPI_6_0_IO_REMAPPING_NAMED_COMP_NODE */                            \
    {                                                                          \
      {                                                                        \
        EFI_ACPI_IORT_TYPE_NAMED_COMP,            /* Type */                   \
        sizeof (ARM_EFI_ACPI_6_0_IO_REMAPPING_DMA_NC_NODE),  /* Length */      \
        4,                                        /* Revision */               \
        0,                                        /* Identifier */             \
        9,                                        /* NumIdMappings */          \
        OFFSET_OF (ARM_EFI_ACPI_6_0_IO_REMAPPING_DMA_NC_NODE,                  \
          DmaIdMap)                               /* IdReference */            \
      },                                                                       \
      0x0,                                        /* Flags */                  \
      0x1,                                        /* CacheCoherent */          \
      0x0,                                        /* AllocationHints */        \
      0x0,                                        /* Reserved */               \
      0x0,                                        /* MemoryAccessFlags */      \
      0x30,                                       /* AddressSizeLimit */       \
    },                                                                         \
    {                                                                          \
        RefName,                                                               \
    },                                                                         \
    /* ID mapping table */                                                     \
    {                                                                          \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 0),  /* Data Channel - 0 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 1),  /* Data Channel - 1 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 2),  /* Data Channel - 2 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 3),  /* Data Channel - 3 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 4),  /* Data Channel - 4 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 5),  /* Data Channel - 5 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 6),  /* Data Channel - 6 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 7),  /* Data Channel - 7 */        \
      EFI_ACPI_DMA_NC_ID_TABLE_INIT(DmaIdx, 8),  /* Instruction channel */     \
    },                                                                         \
  }

#endif /* __SGI_ACPI_HEADER__ */
