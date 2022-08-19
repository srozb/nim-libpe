import def_enums

{.pragma: imphdr_optionalHdr, header: "hdr_optional.h".}

defineEnum(WindowsSubsystem) ## REFERENCE: http:msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
defineEnum(ImageDllCharacteristics)   ##   REFERENCE: http:msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
defineEnum(opt_type_e)

const
  IMAGE_SUBSYSTEM_UNKNOWN* = (0).WindowsSubsystem  ##   Unknown subsystem
  IMAGE_SUBSYSTEM_NATIVE* = (1).WindowsSubsystem  ##   No subsystem required (device drivers and native system processes)
  IMAGE_SUBSYSTEM_WINDOWS_GUI* = (2).WindowsSubsystem  ##   Windows graphical user interface (GUI) subsystem
  IMAGE_SUBSYSTEM_WINDOWS_CUI* = (3).WindowsSubsystem  ##   Windows character-mode user interface (CUI) subsystem
  IMAGE_SUBSYSTEM_OS2_CUI* = (5).WindowsSubsystem  ##   OS/2 CUI subsystem
  IMAGE_SUBSYSTEM_POSIX_CUI* = (7).WindowsSubsystem  ##   POSIX CUI subsystem
  IMAGE_SUBSYSTEM_WINDOWS_CE_GUI* = (9).WindowsSubsystem  ##   Windows CE system
  IMAGE_SUBSYSTEM_EFI_APPLICATION* = (10).WindowsSubsystem  ##   Extensible Firmware Interface (EFI) application
  IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER* = (11).WindowsSubsystem  ##   EFI driver with boot services
  IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER* = (12).WindowsSubsystem  ##   EFI driver with run-time services
  IMAGE_SUBSYSTEM_EFI_ROM* = (13).WindowsSubsystem  ##   EFI ROM image
  IMAGE_SUBSYSTEM_XBOX* = (14).WindowsSubsystem  ##   Xbox system
  IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION* = (16).WindowsSubsystem  ##   Boot application.
  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE* = (0x00000040).ImageDllCharacteristics  ##   IMAGE_DLLCHARACTERISTICS_RESERVED_1			= 0x0001,  ##      IMAGE_DLLCHARACTERISTICS_RESERVED_2			= 0x0002,  ##      IMAGE_DLLCHARACTERISTICS_RESERVED_4			= 0x0004,  ##      IMAGE_DLLCHARACTERISTICS_RESERVED_8			= 0x0008,  ##      The DLL can be relocated at load time.
  IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY* = (0x00000080).ImageDllCharacteristics  ##   Code integrity checks are forced.
  IMAGE_DLLCHARACTERISTICS_NX_COMPAT* = (0x00000100).ImageDllCharacteristics  ##   The image is compatible with data execution prevention (DEP).
  IMAGE_DLLCHARACTERISTICS_NO_ISOLATION* = (0x00000200).ImageDllCharacteristics  ##   The image is isolation aware, but should not be isolated.
  IMAGE_DLLCHARACTERISTICS_NO_SEH* = (0x00000400).ImageDllCharacteristics  ##   The image does not use structured exception handling (SEH).  ##      No handlers can be called in this image.
  IMAGE_DLLCHARACTERISTICS_NO_BIND* = (0x00000800).ImageDllCharacteristics  ##   Do not bind the image.
  IMAGE_DLLCHARACTERISTICS_WDM_DRIVER* = (0x00002000).ImageDllCharacteristics  ##   IMAGE_DLLCHARACTERISTICS_RESERVED_1000		= 0x1000,  ##      A WDM driver.
  IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE* = (0x00008000).ImageDllCharacteristics  ##   IMAGE_DLLCHARACTERISTICS_RESERVED_4000		= 0x4000,  ##      The image is terminal server aware.
  MAGIC_ROM* = (0x00000107).opt_type_e
  MAGIC_PE32* = (0x0000010B).opt_type_e
  MAGIC_PE64* = (0x0000020B).opt_type_e  ##   PE32+

type
  IMAGE_ROM_OPTIONAL_HEADER* {.bycopy, importc, imphdr_optionalHdr.} = object
    Magic*: uint16
    MajorLinkerVersion*: uint8
    MinorLinkerVersion*: uint8
    SizeOfCode*: uint32
    SizeOfInitializedData*: uint32
    SizeOfUninitializedData*: uint32
    AddressOfEntryPoint*: uint32
    BaseOfCode*: uint32
    BaseOfData*: uint32
    BaseOfBss*: uint32
    GprMask*: uint32
    CprMask*: array[4, uint32]
    GpValue*: uint32

  IMAGE_OPTIONAL_HEADER_32* {.bycopy, importc, imphdr_optionalHdr.} = object  ##   REFERENCE: http:msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
    Magic*: uint16
    MajorLinkerVersion*: uint8
    MinorLinkerVersion*: uint8
    SizeOfCode*: uint32
    SizeOfInitializedData*: uint32
    SizeOfUninitializedData*: uint32
    AddressOfEntryPoint*: uint32
    BaseOfCode*: uint32
    BaseOfData*: uint32  ##   only in PE32
    ImageBase*: uint32  ##   only in PE32
    SectionAlignment*: uint32
    FileAlignment*: uint32
    MajorOperatingSystemVersion*: uint16
    MinorOperatingSystemVersion*: uint16
    MajorImageVersion*: uint16
    MinorImageVersion*: uint16
    MajorSubsystemVersion*: uint16
    MinorSubsystemVersion*: uint16
    Reserved1*: uint32
    SizeOfImage*: uint32
    SizeOfHeaders*: uint32
    CheckSum*: uint32
    Subsystem*: uint16  ##   WindowsSubsystem
    DllCharacteristics*: uint16  ##   WindowsSubsystem
    SizeOfStackReserve*: uint32
    SizeOfStackCommit*: uint32
    SizeOfHeapReserve*: uint32
    SizeOfHeapCommit*: uint32
    LoaderFlags*: uint32
    NumberOfRvaAndSizes*: uint32  ##   IMAGE_DATA_DIRECTORY DataDirectory[MAX_DIRECTORIES];

  
  IMAGE_OPTIONAL_HEADER_64* {.bycopy, importc, imphdr_optionalHdr.} = object  ##   REFERENCE: http:msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
    Magic*: uint16
    MajorLinkerVersion*: uint8
    MinorLinkerVersion*: uint8
    SizeOfCode*: uint32
    SizeOfInitializedData*: uint32
    SizeOfUninitializedData*: uint32
    AddressOfEntryPoint*: uint32
    BaseOfCode*: uint32
    ImageBase*: uint64
    SectionAlignment*: uint32
    FileAlignment*: uint32
    MajorOperatingSystemVersion*: uint16
    MinorOperatingSystemVersion*: uint16
    MajorImageVersion*: uint16
    MinorImageVersion*: uint16
    MajorSubsystemVersion*: uint16
    MinorSubsystemVersion*: uint16
    Reserved1*: uint32
    SizeOfImage*: uint32
    SizeOfHeaders*: uint32
    CheckSum*: uint32
    Subsystem*: uint16  ##   WindowsSubsystem
    DllCharacteristics*: uint16  ##   WindowsSubsystem
    SizeOfStackReserve*: uint64
    SizeOfStackCommit*: uint64
    SizeOfHeapReserve*: uint64
    SizeOfHeapCommit*: uint64
    LoaderFlags*: uint32  ##   must be zero
    NumberOfRvaAndSizes*: uint32  ##   must be zero
  
  IMAGE_OPTIONAL_HEADER* {.bycopy, importc, imphdr_optionalHdr.} = object
    `type`*: uint16  ##   opt_type_e
    length*: uint  ##   opt_type_e
    h_32*: ptr IMAGE_OPTIONAL_HEADER_32
    h_64*: ptr IMAGE_OPTIONAL_HEADER_64
