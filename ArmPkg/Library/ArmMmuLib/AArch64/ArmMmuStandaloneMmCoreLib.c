/** @file
*  File managing the MMU for ARMv8 architecture in S-EL0
*
*  Copyright (c) 2017 - 2018, ARM Limited. All rights reserved.
*
*  This program and the accompanying materials
*  are licensed and made available under the terms and conditions of the BSD License
*  which accompanies this distribution.  The full text of the license may be found at
*  http://opensource.org/licenses/bsd-license.php
*
*  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
*  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
*
**/

#include <Uefi.h>
#include <Chipset/AArch64.h>
#include <IndustryStandard/ArmMmSvc.h>

#include <Library/ArmLib.h>
#include <Library/ArmMmuLib.h>
#include <Library/ArmSvcLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

EFI_STATUS
GetMemoryPermissions (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  OUT UINT32                    *MemoryAttributes
  )
{
  ARM_SVC_ARGS  GetMemoryPermissionsSvcArgs = {0};

  GetMemoryPermissionsSvcArgs.Arg0 = ARM_SVC_ID_SP_GET_MEM_ATTRIBUTES_AARCH64;
  GetMemoryPermissionsSvcArgs.Arg1 = BaseAddress;
  GetMemoryPermissionsSvcArgs.Arg2 = 0;
  GetMemoryPermissionsSvcArgs.Arg3 = 0;

  ArmCallSvc (&GetMemoryPermissionsSvcArgs);
  if (GetMemoryPermissionsSvcArgs.Arg0 == ARM_SVC_SPM_RET_INVALID_PARAMS) {
    *MemoryAttributes = 0;
    return EFI_INVALID_PARAMETER;
  }

  *MemoryAttributes = GetMemoryPermissionsSvcArgs.Arg0;
  return EFI_SUCCESS;
}

EFI_STATUS
RequestMemoryPermissionChange (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  IN  UINT64                    Length,
  IN  UINTN                     Permissions
  )
{
  EFI_STATUS    Status;
  ARM_SVC_ARGS  ChangeMemoryPermissionsSvcArgs = {0};

  ChangeMemoryPermissionsSvcArgs.Arg0 = ARM_SVC_ID_SP_SET_MEM_ATTRIBUTES_AARCH64;
  ChangeMemoryPermissionsSvcArgs.Arg1 = BaseAddress;
  ChangeMemoryPermissionsSvcArgs.Arg2 = (Length >= EFI_PAGE_SIZE) ? \
                                         Length >> EFI_PAGE_SHIFT : 1;
  ChangeMemoryPermissionsSvcArgs.Arg3 = Permissions;

  ArmCallSvc (&ChangeMemoryPermissionsSvcArgs);

  Status = ChangeMemoryPermissionsSvcArgs.Arg0;

  switch (Status) {
  case ARM_SVC_SPM_RET_SUCCESS:
    Status = EFI_SUCCESS;
    break;

  case ARM_SVC_SPM_RET_NOT_SUPPORTED:
    Status = EFI_UNSUPPORTED;
    break;

  case ARM_SVC_SPM_RET_INVALID_PARAMS:
    Status = EFI_INVALID_PARAMETER;
    break;

  case ARM_SVC_SPM_RET_DENIED:
    Status = EFI_ACCESS_DENIED;
    break;

  case ARM_SVC_SPM_RET_NO_MEMORY:
    Status = EFI_BAD_BUFFER_SIZE;
    break;

  default:
    Status = EFI_ACCESS_DENIED;
    ASSERT (0);
  }

  return Status;
}

EFI_STATUS
ArmSetMemoryRegionNoExec (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  IN  UINT64                    Length
  )
{
  EFI_STATUS    Status;
  UINT32 MemoryAttributes;

  Status = GetMemoryPermissions (BaseAddress, &MemoryAttributes);
  if (Status != EFI_INVALID_PARAMETER) {
    return RequestMemoryPermissionChange (BaseAddress,
                                          Length,
                                          MemoryAttributes |
                                          (SET_MEM_ATTR_CODE_PERM_XN << SET_MEM_ATTR_CODE_PERM_SHIFT));
  }
  return EFI_INVALID_PARAMETER;
}

EFI_STATUS
ArmClearMemoryRegionNoExec (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  IN  UINT64                    Length
  )
{
  EFI_STATUS    Status;
  UINT32 MemoryAttributes;

  Status = GetMemoryPermissions (BaseAddress, &MemoryAttributes);
  if (Status != EFI_INVALID_PARAMETER) {
    return RequestMemoryPermissionChange (BaseAddress,
                                          Length,
                                          MemoryAttributes &
                                          ~(SET_MEM_ATTR_CODE_PERM_XN << SET_MEM_ATTR_CODE_PERM_SHIFT));
  }
  return EFI_INVALID_PARAMETER;
}

EFI_STATUS
ArmSetMemoryRegionReadOnly (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  IN  UINT64                    Length
  )
{
  EFI_STATUS    Status;
  UINT32 MemoryAttributes;

  Status = GetMemoryPermissions (BaseAddress, &MemoryAttributes);
  if (Status != EFI_INVALID_PARAMETER) {
    return RequestMemoryPermissionChange (BaseAddress,
                                          Length,
                                          MemoryAttributes |
                                          (SET_MEM_ATTR_DATA_PERM_RO << SET_MEM_ATTR_DATA_PERM_SHIFT));
  }
  return EFI_INVALID_PARAMETER;
}

EFI_STATUS
ArmClearMemoryRegionReadOnly (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  IN  UINT64                    Length
  )
{
  EFI_STATUS    Status;
  UINT32 MemoryAttributes;

  Status = GetMemoryPermissions (BaseAddress, &MemoryAttributes);
  if (Status != EFI_INVALID_PARAMETER) {
    return RequestMemoryPermissionChange (BaseAddress,
                                          Length,
                                          SET_MEM_ATTR_MAKE_PERM_REQUEST
                                            ( \
                                             SET_MEM_ATTR_DATA_PERM_RW, \
                                             MemoryAttributes));
  }
  return EFI_INVALID_PARAMETER;
}

EFI_STATUS
EFIAPI
ArmConfigureMmu (
  IN  ARM_MEMORY_REGION_DESCRIPTOR  *MemoryTable,
  OUT VOID                          **TranslationTableBase OPTIONAL,
  OUT UINTN                         *TranslationTableSize OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
ArmMmuStandaloneMmCoreLibConstructor (
  IN EFI_HANDLE            ImageHandle,
  IN EFI_MM_SYSTEM_TABLE   *MmSystemTable
  )
{
  return EFI_SUCCESS;
}
