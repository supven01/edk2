/**@file

Copyright (c) 2006 - 2009, Intel Corporation. All rights reserved.<BR>
Portions copyright (c) 2008 - 2010, Apple Inc. All rights reserved.<BR>
Portions copyright (c) 2011 - 2012, ARM Ltd. All rights reserved.<BR>

This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiDxe.h>

#include <Library/ArmMmuLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffExtraActionLib.h>
#include <Library/PrintLib.h>

typedef RETURN_STATUS (*REGION_PERMISSION_UPDATE_FUNC) (
  IN  EFI_PHYSICAL_ADDRESS      BaseAddress,
  IN  UINT64                    Length
  );

STATIC
RETURN_STATUS
UpdatePeCoffPermissions (
  IN  CONST PE_COFF_LOADER_IMAGE_CONTEXT      *ImageContext,
  IN  REGION_PERMISSION_UPDATE_FUNC           NoExecUpdater,
  IN  REGION_PERMISSION_UPDATE_FUNC           ReadOnlyUpdater
  )
{
  RETURN_STATUS                         Status;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION   Hdr;
  EFI_IMAGE_OPTIONAL_HEADER_UNION       HdrData;
  UINTN                                 Size;
  UINTN                                 ReadSize;
  UINT32                                SectionHeaderOffset;
  UINTN                                 NumberOfSections;
  UINTN                                 Index;
  EFI_IMAGE_SECTION_HEADER              SectionHeader;
  PE_COFF_LOADER_IMAGE_CONTEXT          TmpContext;
  EFI_PHYSICAL_ADDRESS                  Base;

  //
  // We need to copy ImageContext since PeCoffLoaderGetImageInfo ()
  // will mangle the ImageAddress field
  //
  CopyMem (&TmpContext, ImageContext, sizeof (TmpContext));

  if (TmpContext.PeCoffHeaderOffset == 0) {
    Status = PeCoffLoaderGetImageInfo (&TmpContext);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR,
        "%a: PeCoffLoaderGetImageInfo () failed (Status = %r)\n",
        __FUNCTION__, Status));
      return Status;
    }
  }

  if (TmpContext.IsTeImage &&
      TmpContext.ImageAddress == ImageContext->ImageAddress) {
    DEBUG ((DEBUG_INFO, "%a: ignoring XIP TE image at 0x%lx\n", __FUNCTION__,
      ImageContext->ImageAddress));
    return RETURN_SUCCESS;
  }

  if (TmpContext.SectionAlignment < EFI_PAGE_SIZE) {
    //
    // The sections need to be at least 4 KB aligned, since that is the
    // granularity at which we can tighten permissions. So just clear the
    // noexec permissions on the entire region.
    //
    if (!TmpContext.IsTeImage) {
      DEBUG ((DEBUG_WARN,
        "%a: non-TE Image at 0x%lx has SectionAlignment < 4 KB (%lu)\n",
        __FUNCTION__, ImageContext->ImageAddress, TmpContext.SectionAlignment));
    }
    Base = ImageContext->ImageAddress & ~(EFI_PAGE_SIZE - 1);
    Size = ImageContext->ImageAddress - Base + ImageContext->ImageSize;
    return NoExecUpdater (Base, ALIGN_VALUE (Size, EFI_PAGE_SIZE));
  }

  //
  // Read the PE/COFF Header. For PE32 (32-bit) this will read in too much
  // data, but that should not hurt anything. Hdr.Pe32->OptionalHeader.Magic
  // determines if this is a PE32 or PE32+ image. The magic is in the same
  // location in both images.
  //
  Hdr.Union = &HdrData;
  Size = sizeof (EFI_IMAGE_OPTIONAL_HEADER_UNION);
  ReadSize = Size;
  Status = TmpContext.ImageRead (TmpContext.Handle,
                         TmpContext.PeCoffHeaderOffset, &Size, Hdr.Pe32);
  if (RETURN_ERROR (Status) || (Size != ReadSize)) {
    DEBUG ((DEBUG_ERROR,
      "%a: TmpContext.ImageRead () failed (Status = %r)\n",
      __FUNCTION__, Status));
    return Status;
  }

  ASSERT (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE);

  SectionHeaderOffset = TmpContext.PeCoffHeaderOffset + sizeof (UINT32) +
                        sizeof (EFI_IMAGE_FILE_HEADER);
  NumberOfSections    = (UINTN)(Hdr.Pe32->FileHeader.NumberOfSections);

  switch (Hdr.Pe32->OptionalHeader.Magic) {
    case EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
      SectionHeaderOffset += Hdr.Pe32->FileHeader.SizeOfOptionalHeader;
      break;
    case EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
      SectionHeaderOffset += Hdr.Pe32Plus->FileHeader.SizeOfOptionalHeader;
      break;
    default:
      ASSERT (FALSE);
  }

  //
  // Iterate over the sections
  //
  for (Index = 0; Index < NumberOfSections; Index++) {
    //
    // Read section header from file
    //
    Size = sizeof (EFI_IMAGE_SECTION_HEADER);
    ReadSize = Size;
    Status = TmpContext.ImageRead (TmpContext.Handle, SectionHeaderOffset,
                                   &Size, &SectionHeader);
    if (RETURN_ERROR (Status) || (Size != ReadSize)) {
      DEBUG ((DEBUG_ERROR,
        "%a: TmpContext.ImageRead () failed (Status = %r)\n",
        __FUNCTION__, Status));
      return Status;
    }

    Base = TmpContext.ImageAddress + SectionHeader.VirtualAddress;

    if ((SectionHeader.Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) == 0) {

      if ((SectionHeader.Characteristics & EFI_IMAGE_SCN_MEM_WRITE) == 0 &&
          TmpContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {

        DEBUG ((DEBUG_INFO,
          "%a: Mapping section %d of image at 0x%lx with RO-XN permissions and size 0x%x\n",
          __FUNCTION__, Index, Base, SectionHeader.Misc.VirtualSize));
        ReadOnlyUpdater (Base, SectionHeader.Misc.VirtualSize);
      } else {
        DEBUG ((DEBUG_WARN,
          "%a: Mapping section %d of image at 0x%lx with RW-XN permissions and size 0x%x\n",
          __FUNCTION__, Index, Base, SectionHeader.Misc.VirtualSize));
      }
    } else {
        DEBUG ((DEBUG_INFO,
          "%a: Mapping section %d of image at 0x%lx with RO-XN permissions and size 0x%x\n",
           __FUNCTION__, Index, Base, SectionHeader.Misc.VirtualSize));
        ReadOnlyUpdater (Base, SectionHeader.Misc.VirtualSize);

        DEBUG ((DEBUG_INFO,
          "%a: Mapping section %d of image at 0x%lx with RO-X permissions and size 0x%x\n",
          __FUNCTION__, Index, Base, SectionHeader.Misc.VirtualSize));
        NoExecUpdater (Base, SectionHeader.Misc.VirtualSize);
    }

    SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER);
  }
  return RETURN_SUCCESS;
}

/**
  If the build is done on cygwin the paths are cygpaths.
  /cygdrive/c/tmp.txt vs c:\tmp.txt so we need to convert
  them to work with RVD commands

  @param  Name  Path to convert if needed

**/
CHAR8 *
DeCygwinPathIfNeeded (
  IN  CHAR8   *Name,
  IN  CHAR8   *Temp,
  IN  UINTN   Size
  )
{
  CHAR8   *Ptr;
  UINTN   Index;
  UINTN   Index2;

  Ptr = AsciiStrStr (Name, "/cygdrive/");
  if (Ptr == NULL) {
    return Name;
  }

  for (Index = 9, Index2 = 0; (Index < (Size + 9)) && (Ptr[Index] != '\0'); Index++, Index2++) {
    Temp[Index2] = Ptr[Index];
    if (Temp[Index2] == '/') {
      Temp[Index2] = '\\' ;
  }

    if (Index2 == 1) {
      Temp[Index2 - 1] = Ptr[Index];
      Temp[Index2] = ':';
    }
  }

  return Temp;
}


/**
  Performs additional actions after a PE/COFF image has been loaded and relocated.

  If ImageContext is NULL, then ASSERT().

  @param  ImageContext  Pointer to the image context structure that describes the
                        PE/COFF image that has already been loaded and relocated.

**/
VOID
EFIAPI
PeCoffLoaderRelocateImageExtraAction (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
#if !defined(MDEPKG_NDEBUG)
  CHAR8 Temp[512];
#endif

  if (PcdGetBool(PcdStandaloneMmEnable) == TRUE)
  {
     UpdatePeCoffPermissions (ImageContext, ArmClearMemoryRegionNoExec,
                              ArmSetMemoryRegionReadOnly);
  }

  if (ImageContext->PdbPointer) {
#ifdef __CC_ARM
#if (__ARMCC_VERSION < 500000)
    // Print out the command for the RVD debugger to load symbols for this image
    DEBUG ((DEBUG_LOAD | DEBUG_INFO, "load /a /ni /np %a &0x%p\n", DeCygwinPathIfNeeded (ImageContext->PdbPointer, Temp, sizeof (Temp)), (UINTN)(ImageContext->ImageAddress + ImageContext->SizeOfHeaders)));
#else
    // Print out the command for the DS-5 to load symbols for this image
    DEBUG ((DEBUG_LOAD | DEBUG_INFO, "add-symbol-file %a 0x%p\n", DeCygwinPathIfNeeded (ImageContext->PdbPointer, Temp, sizeof (Temp)), (UINTN)(ImageContext->ImageAddress + ImageContext->SizeOfHeaders)));
#endif
#elif __GNUC__
    // This may not work correctly if you generate PE/COFF directlyas then the Offset would not be required
    DEBUG ((DEBUG_LOAD | DEBUG_INFO, "add-symbol-file %a 0x%p\n", DeCygwinPathIfNeeded (ImageContext->PdbPointer, Temp, sizeof (Temp)), (UINTN)(ImageContext->ImageAddress + ImageContext->SizeOfHeaders)));
#else
    DEBUG ((DEBUG_LOAD | DEBUG_INFO, "Loading driver at 0x%11p EntryPoint=0x%11p\n", (VOID *)(UINTN) ImageContext->ImageAddress, FUNCTION_ENTRY_POINT (ImageContext->EntryPoint)));
#endif
  } else {
    DEBUG ((DEBUG_LOAD | DEBUG_INFO, "Loading driver at 0x%11p EntryPoint=0x%11p\n", (VOID *)(UINTN) ImageContext->ImageAddress, FUNCTION_ENTRY_POINT (ImageContext->EntryPoint)));
  }
}



/**
  Performs additional actions just before a PE/COFF image is unloaded.  Any resources
  that were allocated by PeCoffLoaderRelocateImageExtraAction() must be freed.

  If ImageContext is NULL, then ASSERT().

  @param  ImageContext  Pointer to the image context structure that describes the
                        PE/COFF image that is being unloaded.

**/
VOID
EFIAPI
PeCoffLoaderUnloadImageExtraAction (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
#if !defined(MDEPKG_NDEBUG)
  CHAR8 Temp[512];
#endif

  if (PcdGetBool(PcdStandaloneMmEnable) == TRUE)
  {
     UpdatePeCoffPermissions (ImageContext, ArmSetMemoryRegionNoExec,
                              ArmClearMemoryRegionReadOnly);
  }

  if (ImageContext->PdbPointer) {
#ifdef __CC_ARM
    // Print out the command for the RVD debugger to load symbols for this image
    DEBUG ((DEBUG_ERROR, "unload symbols_only %a\n", DeCygwinPathIfNeeded (ImageContext->PdbPointer, Temp, sizeof (Temp))));
#elif __GNUC__
    // This may not work correctly if you generate PE/COFF directlyas then the Offset would not be required
    DEBUG ((DEBUG_ERROR, "remove-symbol-file %a 0x%08x\n", DeCygwinPathIfNeeded (ImageContext->PdbPointer, Temp, sizeof (Temp)), (UINTN)(ImageContext->ImageAddress + ImageContext->SizeOfHeaders)));
#else
    DEBUG ((DEBUG_ERROR, "Unloading %a\n", ImageContext->PdbPointer));
#endif
  } else {
    DEBUG ((DEBUG_ERROR, "Unloading driver at 0x%11p\n", (VOID *)(UINTN) ImageContext->ImageAddress));
  }
}
