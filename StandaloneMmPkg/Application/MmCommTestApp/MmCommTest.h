/** @file
  GUIDs for MM Event.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2016 - 2018, ARM Limited. All rights reserved.<BR>

This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __MM_COMM_TEST_H__
#define __MM_COMM_TEST_H__

#define MM_COMM_TEST_GUID \
  { 0xa37721e4, 0x8c0b, 0x4bca, { 0xb5, 0xe8, 0xe9, 0x2, 0xa0, 0x25, 0x51, 0x4e }}

extern EFI_GUID gMmCommTestGuid;

#pragma pack(1)
typedef struct {
  EFI_SYSTEM_TABLE      EfiSystemTable;
} EFI_MM_COMMUNICATE_TEST_DATA;

typedef struct {
  EFI_GUID                         HeaderGuid;
  UINTN                            MessageLength;
  EFI_MM_COMMUNICATE_TEST_DATA     Data;
} EFI_MM_COMMUNICATE_TEST;
#pragma pack()

#endif
