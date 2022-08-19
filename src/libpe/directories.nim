import def_enums

{.pragma: impdirectoriesHdr, header: "directories.h".}

defineEnum(ImageDirectoryEntry)  ##   Directory entries

const
  IMAGE_DIRECTORY_ENTRY_EXPORT* = (0).ImageDirectoryEntry  ##   Export Table
  IMAGE_DIRECTORY_ENTRY_IMPORT* = (1).ImageDirectoryEntry  ##   Import Table
  IMAGE_DIRECTORY_ENTRY_RESOURCE* = (2).ImageDirectoryEntry  ##   Resource Table
  IMAGE_DIRECTORY_ENTRY_EXCEPTION* = (3).ImageDirectoryEntry  ##   Exception Table
  IMAGE_DIRECTORY_ENTRY_SECURITY* = (4).ImageDirectoryEntry  ##   Certificate Table
  IMAGE_DIRECTORY_ENTRY_BASERELOC* = (5).ImageDirectoryEntry  ##   Base Relocation Table
  IMAGE_DIRECTORY_ENTRY_DEBUG* = (6).ImageDirectoryEntry  ##   Debug
  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE* = (7).ImageDirectoryEntry  ##   Architecture
  IMAGE_DIRECTORY_ENTRY_GLOBALPTR* = (8).ImageDirectoryEntry  ##   Global Ptr
  IMAGE_DIRECTORY_ENTRY_TLS* = (9).ImageDirectoryEntry  ##   TLS Table
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG* = (10).ImageDirectoryEntry  ##   Load Config Table
  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT* = (11).ImageDirectoryEntry  ##   Bound Import
  IMAGE_DIRECTORY_ENTRY_IAT* = (12).ImageDirectoryEntry  ##   IAT
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT* = (13).ImageDirectoryEntry  ##   Delay Import Descriptor
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR* = (14).ImageDirectoryEntry  ##   CLR Runtime Header
  IMAGE_DIRECTORY_RESERVED* = (15).ImageDirectoryEntry  ##   Reserved, must be zero

type
  IMAGE_EXPORT_DIRECTORY* {.bycopy, importc, impdirectoriesHdr.} = object
    Characteristics*: uint32
    TimeDateStamp*: uint32
    MajorVersion*: uint16
    MinorVersion*: uint16
    Name*: uint32
    Base*: uint32
    NumberOfFunctions*: uint32
    NumberOfNames*: uint32
    AddressOfFunctions*: uint32
    AddressOfNames*: uint32
    AddressOfNameOrdinals*: uint32

  IMAGE_TLS_DIRECTORY32* {.bycopy, importc, impdirectoriesHdr.} = object
    StartAddressOfRawData*: uint32
    EndAddressOfRawData*: uint32
    AddressOfIndex*: uint32
    AddressOfCallBacks*: uint32  ##   PIMAGE_TLS_CALLBACK
    SizeOfZeroFill*: uint32  ##   PIMAGE_TLS_CALLBACK
    Characteristics*: uint32  ##   reserved for future use

  IMAGE_TLS_DIRECTORY64* {.bycopy, importc, impdirectoriesHdr.} = object
    StartAddressOfRawData*: uint64
    EndAddressOfRawData*: uint64
    AddressOfIndex*: uint64
    AddressOfCallBacks*: uint64
    SizeOfZeroFill*: uint32
    Characteristics*: uint32

  IMAGE_DATA_DIRECTORY* {.bycopy, importc, impdirectoriesHdr.} = object
    VirtualAddress*: uint32
    Size*: uint32
