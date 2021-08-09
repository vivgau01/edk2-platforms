/** @file
  Secondary System Description Table (SSDT) for Non-PCIe IO
  Virtualization Block.

  The IO virtualization block present on reference design platforms
  such as RD-N2 and RD-N2-Cfg1 allows connecting PCIe and non-PCIe
  devices. The non-discoverable (non-PCIe) devices that are connected
  to the IO virtualization block include two PL011 UART and two PL330
  DMA controllers.

  Copyright (c) 2022, Arm Ltd. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Specification Reference:
    - ACPI 6.4, Chapter 5, Section 5.2.11.2, Secondary System Description Table
**/

#include "SgiPlatform.h"
#include "SgiAcpiHeader.h"

DefinitionBlock ("SsdtIoVirtBlk.aml", "SSDT", 2, "ARMLTD", "ARMSGI",
                 EFI_ACPI_ARM_OEM_REVISION) {
  Scope (_SB) {

    // IO Virtualization Block - PL011 UART0
    Device (COM4) {
      Name (_HID, "ARMH0011")
      Name (_UID, 4)
      Name (_STA, 0xF)

      Name (_CRS, ResourceTemplate () {
        QWordMemory (
          ResourceProducer,
          PosDecode,
          MinFixed,
          MaxFixed,
          NonCacheable,
          ReadWrite,
          0x0,
          FixedPcdGet64 (PcdIoVirtBlkUart0Base),
          FixedPcdGet64 (PcdIoVirtBlkUart0End),
          0x0,
          FixedPcdGet32 (PcdIoVirtBlkUart0Size),
          ,
          ,
          ,
          AddressRangeMemory,
          TypeStatic
        )

        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkUart0Interrupt)
        }
      })
    }

    // IO Virtualization Block - PL011 UART1
    Device (COM5) {
      Name (_HID, "ARMH0011")
      Name (_UID, 5)
      Name (_STA, 0xF)

      Name (_CRS, ResourceTemplate () {
        QWordMemory (
          ResourceProducer,
          PosDecode,
          MinFixed,
          MaxFixed,
          NonCacheable,
          ReadWrite,
          0x0,
          FixedPcdGet64 (PcdIoVirtBlkUart1Base),
          FixedPcdGet64 (PcdIoVirtBlkUart1End),
          0x0,
          FixedPcdGet32 (PcdIoVirtBlkUart1Size),
          ,
          ,
          ,
          AddressRangeMemory,
          TypeStatic
        )

        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkUart1Interrupt)
        }
      })
    }

    // IO Virtualization Block - PL330 DMA0
    Device (\_SB.DMA0) {
      Name (_HID, "ARMH0330")
      Name (_UID, 0)
      Name (_CCA, 1)
      Name (_STA, 0xF)

      Name (_CRS, ResourceTemplate () {
        QWordMemory (
          ResourceProducer,
          PosDecode,
          MinFixed,
          MaxFixed,
          NonCacheable,
          ReadWrite,
          0x0,
          FixedPcdGet64 (PcdIoVirtBlkDma0Base),
          FixedPcdGet64 (PcdIoVirtBlkDma0End),
          0x0,
          FixedPcdGet32 (PcdIoVirtBlkDma0Size),
          ,
          ,
          ,
          AddressRangeMemory,
          TypeStatic
        )

        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch0Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch1Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch2Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch3Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch4Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch5Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch6Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0Ch7Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma0AbortGsiv)
        }
      })
    }

    // IO Virtualization Block - PL330 DMA1
    Device (\_SB.DMA1) {
      Name (_HID, "ARMH0330")
      Name (_UID, 1)
      Name (_CCA, 1)
      Name (_STA, 0xF)

      Name (_CRS, ResourceTemplate () {
        QWordMemory (
          ResourceProducer,
          PosDecode,
          MinFixed,
          MaxFixed,
          NonCacheable,
          ReadWrite,
          0x0,
          FixedPcdGet64 (PcdIoVirtBlkDma1Base),
          FixedPcdGet64 (PcdIoVirtBlkDma1End),
          0x0,
          FixedPcdGet32 (PcdIoVirtBlkDma1Size),
          ,
          ,
          ,
          AddressRangeMemory,
          TypeStatic
        )

        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch0Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch1Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch2Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch3Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch4Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch5Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch6Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1Ch7Gsiv)
        }
        Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {
          FixedPcdGet32 (PcdIoVirtBlkDma1AbortGsiv)
        }
      })
    }
  } // Scope(_SB)
}
