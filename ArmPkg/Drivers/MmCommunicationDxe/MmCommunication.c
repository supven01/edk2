/** @file

  Copyright (c) 2016-2018, ARM Limited. All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/ArmLib.h>
#include <Library/ArmSmcLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Protocol/MmCommunication.h>

#include <IndustryStandard/ArmStdSmc.h>

#define MM_MAJOR_VER_MASK        0xFFFF0000
#define MM_MINOR_VER_MASK        0x0000FFFF
#define MM_MAJOR_VER_SHIFT       16

const UINT32 MM_MAJOR_VER = 1;
const UINT32 MM_MINOR_VER = 0;

//
// Address, Length of the pre-allocated buffer for communication with the secure
// world.
//
STATIC ARM_MEMORY_REGION_DESCRIPTOR  mNsCommBuffMemRegion;

// Notification event when virtual address map is set.
STATIC EFI_EVENT  mSetVirtualAddressMapEvent;

//
// Handle to install the MM Communication Protocol
//
STATIC EFI_HANDLE  mMmCommunicateHandle;

/**
  Communicates with a registered handler.

  This function provides an interface to send and receive messages to the
  Standalone MM environment on behalf of UEFI services.  This function is part
  of the MM Communication Protocol that may be called in physical mode prior to
  SetVirtualAddressMap() and in virtual mode after SetVirtualAddressMap().

  @param[in]      This                The EFI_MM_COMMUNICATION_PROTOCOL
                                      instance.
  @param[in, out] CommBuffer          A pointer to the buffer to convey
                                      into MMRAM.
  @param[in, out] CommSize            The size of the data buffer being
                                      passed in. This is optional.

  @retval EFI_SUCCESS                 The message was successfully posted.
  @retval EFI_INVALID_PARAMETER       The CommBuffer was NULL.
  @retval EFI_BAD_BUFFER_SIZE         The buffer size is incorrect for the MM
                                      implementation. If this error is
                                      returned, the MessageLength field in
                                      the CommBuffer header or the integer
                                      pointed by CommSize are updated to reflect
                                      the maximum payload size the
                                      implementation can accommodate.
  @retval EFI_ACCESS_DENIED           The CommunicateBuffer parameter
                                      or CommSize parameter, if not omitted,
                                      are in address range that cannot be
                                      accessed by the MM environment
**/
STATIC
EFI_STATUS
EFIAPI
MmCommunicationCommunicate (
  IN CONST EFI_MM_COMMUNICATION_PROTOCOL  *This,
  IN OUT VOID                             *CommBuffer,
  IN OUT UINTN                            *CommSize OPTIONAL
  )
{
  EFI_MM_COMMUNICATE_HEADER   *CommunicateHeader;
  ARM_SMC_ARGS                CommunicateSmcArgs;
  EFI_STATUS                  Status;
  UINTN                       BufferSize;

  Status = EFI_ACCESS_DENIED;
  BufferSize = 0;

  ZeroMem (&CommunicateSmcArgs, sizeof (ARM_SMC_ARGS));

  //
  // Check parameters
  //
  if (CommBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CommunicateHeader = CommBuffer;
  // CommBuffer is a mandatory parameter. Hence, Rely on
  // MessageLength + Header to ascertain the
  // total size of the communication payload rather than
  // rely on optional CommSize parameter
  BufferSize = CommunicateHeader->MessageLength +
               sizeof (CommunicateHeader->HeaderGuid) +
               sizeof (CommunicateHeader->MessageLength);

  // If the length of the CommBuffer is 0 then return the expected length.
  if (CommSize) {
    // This case can be used by the consumer of this driver to find out the
    // max size that can be used for allocating CommBuffer.
    if ((*CommSize == 0) ||
        (*CommSize > mNsCommBuffMemRegion.Length)) {
      *CommSize = mNsCommBuffMemRegion.Length;
      return EFI_BAD_BUFFER_SIZE;
    }
    //
    // CommSize must match MessageLength + sizeof (EFI_MM_COMMUNICATE_HEADER);
    //
    if (*CommSize != BufferSize) {
        return EFI_INVALID_PARAMETER;
    }
  }

  //
  // If the buffer size is 0 or greater than what can be tolerated by the MM
  // environment then return the expected size.
  //
  if ((BufferSize == 0) ||
      (BufferSize > mNsCommBuffMemRegion.Length)) {
    CommunicateHeader->MessageLength = mNsCommBuffMemRegion.Length -
                                       sizeof (CommunicateHeader->HeaderGuid) -
                                       sizeof (CommunicateHeader->MessageLength);
    return EFI_BAD_BUFFER_SIZE;
  }

  // SMC Function ID
  CommunicateSmcArgs.Arg0 = ARM_SMC_ID_MM_COMMUNICATE_AARCH64;

  // Reserved for Future. Must be Zero.
  CommunicateSmcArgs.Arg1 = 0;

  // Copy Communication Payload
  CopyMem ((VOID *)mNsCommBuffMemRegion.VirtualBase, CommBuffer, BufferSize);

  // For the SMC64 version, this parameter is a 64-bit Physical Address (PA)
  // or Intermediate Physical Address (IPA).
  // For the SMC32 version, this parameter is a 32-bit PA or IPA.
  CommunicateSmcArgs.Arg2 = (UINTN)mNsCommBuffMemRegion.PhysicalBase;

  // comm_size_address is a PA or an IPA that holds the size of the
  // communication buffer being passed in. This parameter is optional
  // and can be omitted by passing a zero.
  // ARM does not recommend using it since this might require the
  // implementation to create a separate memory mapping for the parameter.
  // ARM recommends storing the buffer size in the buffer itself.
  CommunicateSmcArgs.Arg3 = 0;

  // Call the Standalone MM environment.
  ArmCallSmc (&CommunicateSmcArgs);

  switch (CommunicateSmcArgs.Arg0) {
  case ARM_SMC_MM_RET_SUCCESS:
    ZeroMem (CommBuffer, BufferSize);
    // On exit, the size of data being returned is inferred from
    // MessageLength + Header.
    CommunicateHeader = (EFI_MM_COMMUNICATE_HEADER *)mNsCommBuffMemRegion.VirtualBase;
    BufferSize = CommunicateHeader->MessageLength +
                 sizeof (CommunicateHeader->HeaderGuid) +
                 sizeof (CommunicateHeader->MessageLength);

    // Note: Very important to ensure that the consumer of this driver
    // has allocated CommBuffer sufficiently so that the return data
    // can be copied. Otherwise, this will lead to buffer overflow.
    // Assumption: CommBuffer = malloc (mNsCommBuffMemRegion.Length)
    // This guidance should be in the PI specification. TODO: ECR.
    CopyMem (CommBuffer,
             (const VOID *)mNsCommBuffMemRegion.VirtualBase,
             BufferSize);
    Status = EFI_SUCCESS;
    break;

  case ARM_SMC_MM_RET_INVALID_PARAMS:
    Status = EFI_INVALID_PARAMETER;
    break;

  case ARM_SMC_MM_RET_DENIED:
    Status = EFI_ACCESS_DENIED;
    break;

  case ARM_SMC_MM_RET_NO_MEMORY:
    // Unexpected error since the CommSize was checked for zero length
    // prior to issuing the SMC
  default:
    Status = EFI_ACCESS_DENIED;
    ASSERT (0);
  }

  return Status;
}

//
// MM Communication Protocol instance
//
EFI_MM_COMMUNICATION_PROTOCOL  mMmCommunication = {
  MmCommunicationCommunicate
};

/**
  Notification callback on SetVirtualAddressMap event.

  This function notifies the MM communication protocol interface on
  SetVirtualAddressMap event and converts pointers used in this driver
  from physical to virtual address.

  @param  Event          SetVirtualAddressMap event.
  @param  Context        A context when the SetVirtualAddressMap triggered.

  @retval EFI_SUCCESS    The function executed successfully.
  @retval Other          Some error occurred when executing this function.

**/
STATIC
VOID
EFIAPI
NotifySetVirtualAddressMap (
  IN EFI_EVENT  Event,
  IN VOID      *Context
  )
{
  EFI_STATUS  Status;

  Status = gRT->ConvertPointer (EFI_OPTIONAL_PTR,
                                (VOID **)&mNsCommBuffMemRegion.VirtualBase
                               );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "NotifySetVirtualAddressMap():"
            " Unable to convert MM runtime pointer. Status:0x%r\n", Status));
  }

}

STATIC
EFI_STATUS
GetMmVersion ()
{
  EFI_STATUS   Status;
  UINT16       MmMajorVersion;
  UINT16       MmMinorVersion;
  UINT32       MmVersion;
  ARM_SMC_ARGS MmVersionArgs;

  MmVersionArgs.Arg0 = ARM_SMC_ID_MM_VERSION_AARCH32;

  ArmCallSmc (&MmVersionArgs);

  MmVersion = MmVersionArgs.Arg0;

  MmMajorVersion = ((MmVersion & MM_MAJOR_VER_MASK) >> MM_MAJOR_VER_SHIFT);
  MmMinorVersion = ((MmVersion & MM_MINOR_VER_MASK) >> 0);

  // Different major revision values indicate possibly incompatible functions.
  // For two revisions, A and B, for which the major revision values are
  // identical, if the minor revision value of revision B is greater than
  // the minor revision value of revision A, then every function in
  // revision A must work in a compatible way with revision B.
  // However, it is possible for revision B to have a higher
  // function count than revision A.
  if ((MmMajorVersion == MM_MAJOR_VER) &&
      (MmMinorVersion >= MM_MINOR_VER))
  {
    DEBUG ((DEBUG_INFO, "MM Version: Major=0x%x, Minor=0x%x\n",
           MmMajorVersion, MmMinorVersion));
    Status = EFI_SUCCESS;
  }
  else
  {
    DEBUG ((DEBUG_ERROR, "Incompatible MM Versions.\n Current Version: Major=0x%x, Minor=0x%x.\n Expected: Major=0x%x, Minor>=0x%x.\n",
            MmMajorVersion, MmMinorVersion, MM_MAJOR_VER, MM_MINOR_VER));
    Status = EFI_UNSUPPORTED;
  }

  return Status;
}

/**
  The Entry Point for MM Communication

  This function installs the MM communication protocol interface and finds out
  what type of buffer management will be required prior to invoking the
  communication SMC.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
MmCommunicationInitialize (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                 Status;

    // Get Secure Partition Manager Version Information
  Status = GetMmVersion ();
  if (EFI_ERROR(Status)) {
    goto ReturnErrorStatus;
  }

  mNsCommBuffMemRegion.PhysicalBase = PcdGet64 (PcdMmBufferBase);
  // During boot , Virtual and Physical are same
  mNsCommBuffMemRegion.VirtualBase = mNsCommBuffMemRegion.PhysicalBase;
  mNsCommBuffMemRegion.Length = PcdGet64 (PcdMmBufferSize);

  if (mNsCommBuffMemRegion.PhysicalBase == 0) {
    DEBUG ((DEBUG_ERROR, "MmCommunicateInitialize: "
            "Invalid MM Buffer Base Address.\n"));
    goto ReturnErrorStatus;
  }

  if (mNsCommBuffMemRegion.Length == 0) {
    DEBUG ((DEBUG_ERROR, "MmCommunicateInitialize: "
            "Maximum Buffer Size is zero.\n"));
    goto ReturnErrorStatus;
  }

  Status = gDS->AddMemorySpace (EfiGcdMemoryTypeSystemMemory,
                                mNsCommBuffMemRegion.PhysicalBase,
                                mNsCommBuffMemRegion.Length,
                                EFI_MEMORY_WB |
                                EFI_MEMORY_XP |
                                EFI_MEMORY_RUNTIME);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MmCommunicateInitialize: "
            "Failed to add MM-NS Buffer Memory Space\n"));
    goto ReturnErrorStatus;
  }

  Status = gDS->SetMemorySpaceAttributes (mNsCommBuffMemRegion.PhysicalBase,
                                          mNsCommBuffMemRegion.Length,
                                          EFI_MEMORY_WB | EFI_MEMORY_XP);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MmCommunicateInitialize: "
            "Failed to set MM-NS Buffer Memory attributes\n"));
    goto CleanAddedMemorySpace;
  }

  Status = gBS->AllocatePages (AllocateAddress,
                               EfiRuntimeServicesData,
                               EFI_SIZE_TO_PAGES (mNsCommBuffMemRegion.Length),
                               &mNsCommBuffMemRegion.PhysicalBase);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MmCommunicateInitialize: "
            "Failed to allocate MM-NS Buffer Memory Space\n"));
    goto CleanAddedMemorySpace;
  }

  // Install the communication protocol
  Status = gBS->InstallProtocolInterface (&mMmCommunicateHandle,
                                          &gEfiMmCommunicationProtocolGuid,
                                          EFI_NATIVE_INTERFACE,
                                          &mMmCommunication);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "MmCommunicationInitialize: "
            "Failed to install MM communication protocol\n"));
    goto CleanAllocatedPages;
  }

  // Register notification callback when  virtual address is associated
  // with the physical address.
  // Create a Set Virtual Address Map event.
  //
  Status = gBS->CreateEvent (EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,  // Type
                             TPL_NOTIFY,                         // NotifyTpl
                             NotifySetVirtualAddressMap,         // NotifyFunction
                             NULL,                               // NotifyContext
                             &mSetVirtualAddressMapEvent         // Event
                            );
  if (Status == EFI_SUCCESS) {
    return Status;
  }

  gBS->UninstallProtocolInterface(mMmCommunicateHandle,
                                  &gEfiMmCommunicationProtocolGuid,
                                  &mMmCommunication);

CleanAllocatedPages:
  gBS->FreePages (mNsCommBuffMemRegion.PhysicalBase,
                  EFI_SIZE_TO_PAGES (mNsCommBuffMemRegion.Length));

CleanAddedMemorySpace:
  gDS->RemoveMemorySpace (mNsCommBuffMemRegion.PhysicalBase,
                          mNsCommBuffMemRegion.Length);

ReturnErrorStatus:
  return EFI_INVALID_PARAMETER;
}
