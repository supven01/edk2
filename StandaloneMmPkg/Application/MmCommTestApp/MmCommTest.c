/** @file
  This sample application demos how to communicate
  with secure partition using MM communication protocol

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include "MmCommTest.h"

#include <Library/ArmSmcLib.h>

#include <Protocol/MmCommunication.h>

EFI_MM_COMMUNICATION_PROTOCOL  *mMmCommunication = NULL;

EFI_STATUS
MmIplNotifyCommTest (
  VOID
  )
{
  EFI_MM_COMMUNICATE_TEST    MmCommTest;
  UINTN                      Size;

  DEBUG ((DEBUG_INFO, "MmIplNotifyCommTest\n"));

  CopyGuid (&MmCommTest.HeaderGuid, &gMmCommTestGuid);
  CopyMem (&MmCommTest.Data.EfiSystemTable, gST, sizeof (EFI_SYSTEM_TABLE));
  MmCommTest.MessageLength = sizeof (EFI_MM_COMMUNICATE_TEST_DATA);

  //
  // Generate the MM_COMMUNICATE SMC and return the result
  //
  Size = sizeof (MmCommTest);
  return mMmCommunication->Communicate (NULL, &MmCommTest, &Size);
}

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmCommTestEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (&gEfiMmCommunicationProtocolGuid, NULL, (VOID **) &mMmCommunication);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return MmIplNotifyCommTest ();
}
