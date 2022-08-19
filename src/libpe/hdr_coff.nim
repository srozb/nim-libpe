import def_enums

{.pragma: imphdr_coffHdr, header: "hdr_coff.h".}

defineEnum(MachineType)
defineEnum(ImageCharacteristics)

const
  IMAGE_FILE_MACHINE_UNKNOWN* = (0x00000000).MachineType
  IMAGE_FILE_MACHINE_AM33* = (0x000001D3).MachineType
  IMAGE_FILE_MACHINE_AMD64* = (0x00008664).MachineType
  IMAGE_FILE_MACHINE_ARM* = (0x000001C0).MachineType
  IMAGE_FILE_MACHINE_ARMV7* = (0x000001C4).MachineType
  IMAGE_FILE_MACHINE_CEE* = (0x0000C0EE).MachineType
  IMAGE_FILE_MACHINE_EBC* = (0x00000EBC).MachineType
  IMAGE_FILE_MACHINE_I386* = (0x0000014C).MachineType
  IMAGE_FILE_MACHINE_IA64* = (0x00000200).MachineType
  IMAGE_FILE_MACHINE_M32R* = (0x00009041).MachineType
  IMAGE_FILE_MACHINE_MIPS16* = (0x00000266).MachineType
  IMAGE_FILE_MACHINE_MIPSFPU* = (0x00000366).MachineType
  IMAGE_FILE_MACHINE_MIPSFPU16* = (0x00000466).MachineType
  IMAGE_FILE_MACHINE_POWERPC* = (0x000001F0).MachineType
  IMAGE_FILE_MACHINE_POWERPCFP* = (0x000001F1).MachineType
  IMAGE_FILE_MACHINE_R4000* = (0x00000166).MachineType
  IMAGE_FILE_MACHINE_SH3* = (0x000001A2).MachineType
  IMAGE_FILE_MACHINE_SH3DSP* = (0x000001A3).MachineType
  IMAGE_FILE_MACHINE_SH4* = (0x000001A6).MachineType
  IMAGE_FILE_MACHINE_SH5* = (0x000001A8).MachineType
  IMAGE_FILE_MACHINE_THUMB* = (0x000001C2).MachineType
  IMAGE_FILE_MACHINE_WCEMIPSV2* = (0x00000169).MachineType
  IMAGE_FILE_RELOCS_STRIPPED* = (0x00000001).ImageCharacteristics  ##   Image only, Windows CE, Windows NT and above. Indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from EXEs.
  IMAGE_FILE_EXECUTABLE_IMAGE* = (0x00000002).ImageCharacteristics  ##   Image only. Indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
  IMAGE_FILE_LINE_NUMS_STRIPPED* = (0x00000004).ImageCharacteristics  ##   COFF line numbers have been removed. Deprecated and should be zero.
  IMAGE_FILE_LOCAL_SYMS_STRIPPED* = (0x00000008).ImageCharacteristics  ##   COFF symbol table entries for local symbols have been removed. Deprecated and should be zero.
  IMAGE_FILE_AGGRESSIVE_WS_TRIM* = (0x00000010).ImageCharacteristics  ##   Obsolete. Aggressively trim working set. Deprecated in Windows 2000 and later. Must be zero.
  IMAGE_FILE_LARGE_ADDRESS_AWARE* = (0x00000020).ImageCharacteristics  ##   App can handle > 2gb addresses.
  IMAGE_FILE_RESERVED* = (0x00000040).ImageCharacteristics  ##   Reserved for future use.
  IMAGE_FILE_BYTES_REVERSED_LO* = (0x00000080).ImageCharacteristics  ##   Little endian: LSB precedes MSB in memory. Deprecated and should be zero.
  IMAGE_FILE_32BIT_MACHINE* = (0x00000100).ImageCharacteristics  ##   Machine based on 32-bit-word architecture.
  IMAGE_FILE_DEBUG_STRIPPED* = (0x00000200).ImageCharacteristics  ##   Debugging information removed from image file.
  IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP* = (0x00000400).ImageCharacteristics  ##   If image is on removable media, fully load it and copy it to the swap file.
  IMAGE_FILE_NET_RUN_FROM_SWAP* = (0x00000800).ImageCharacteristics  ##   If image is on network media, fully load it and copy it to the swap file.
  IMAGE_FILE_SYSTEM* = (0x00001000).ImageCharacteristics  ##   The image file is a system file, not a user program.
  IMAGE_FILE_DLL* = (0x00002000).ImageCharacteristics  ##   The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
  IMAGE_FILE_UP_SYSTEM_ONLY* = (0x00004000).ImageCharacteristics  ##   File should be run only on a UP machine.
  IMAGE_FILE_BYTES_REVERSED_HI* = (0x00008000).ImageCharacteristics  ##   Big endian: MSB precedes LSB in memory. Deprecated and should be zero.

type
  IMAGE_COFF_HEADER* {.bycopy, importc, imphdr_coffHdr.} = object
    Machine*: uint16  ##  MachineType
    NumberOfSections*: uint16  ##  MachineType
    TimeDateStamp*: uint32
    PointerToSymbolTable*: uint32
    NumberOfSymbols*: uint32
    SizeOfOptionalHeader*: uint16
    Characteristics*: uint16  ##  ImageCharacteristics
