/** @file
*
*  Copyright (c) 2018-2022, ARM Limited. All rights reserved.
*
*  SPDX-License-Identifier: BSD-2-Clause-Patent
*
**/

#include <Library/AcpiLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PL011UartLib.h>

#include <SgiPlatform.h>

VOID
InitVirtioDevices (
  VOID
  );

/**
  Initialize UART controllers connected to IO Virtualization block.

  Use PL011UartLib Library to initialize UART controllers connected
  to x4_0 and x8 port of the IO Virtualization block on infrastructure
  reference design (RD) platforms.

  @retval  None
**/
STATIC
VOID
InitIoVirtBlkUartControllers (VOID)
{
  EFI_STATUS          Status;
  EFI_PARITY_TYPE     Parity;
  EFI_STOP_BITS_TYPE  StopBits;
  UINT64              BaudRate;
  UINT32              ReceiveFifoDepth;
  UINT8               DataBits;

  if (!FeaturePcdGet (PcdIoVirtBlkNonDiscoverable))
    return;

  ReceiveFifoDepth = 0;
  Parity = 1;
  DataBits = 8;
  StopBits = 1;
  BaudRate = 115200;

  // Use PL011Uart Library to initialize the x4: PL011_UART0
  Status = PL011UartInitializePort (
             (UINTN)FixedPcdGet64 (PcdIoVirtBlkUart0Base),
             FixedPcdGet32 (PcdSerialDbgUartClkInHz),
             &BaudRate,
             &ReceiveFifoDepth,
             &Parity,
             &DataBits,
             &StopBits
             );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Failed to init PL011_UART0 on IO Virt Block port x4_0, status: %r\n",
      Status
      ));
  }

  // Use PL011Uart Library to initialize the x8: PL011_UART1
  Status = PL011UartInitializePort (
             (UINTN)FixedPcdGet64 (PcdIoVirtBlkUart1Base),
             FixedPcdGet32 (PcdSerialDbgUartClkInHz),
             &BaudRate,
             &ReceiveFifoDepth,
             &Parity,
             &DataBits,
             &StopBits
             );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Failed to init PL011_UART1 on IO Virt Block port x8, status: %r\n",
      Status
      ));
  }
}

EFI_STATUS
EFIAPI
ArmSgiPkgEntryPoint (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS              Status;

  Status = LocateAndInstallAcpiFromFv (&gArmSgiAcpiTablesGuid);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to install ACPI tables\n", __FUNCTION__));
    return Status;
  }

  InitVirtioDevices ();
  InitIoVirtBlkUartControllers ();

  return Status;
}
