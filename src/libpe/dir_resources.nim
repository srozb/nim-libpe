import def_enums

{.pragma: impdir_resourcesHdr, header: "dir_resources.h".}

defineEnum(ResourceType)

const
  IMAGE_RESOURCE_NAME_IS_STRING* = 0x80000000
  IMAGE_RESOURCE_DATA_IS_DIRECTORY* = 0x80000000
  RT_CURSOR* = (1).ResourceType  ##   cursor image
  RT_BITMAP* = (2).ResourceType  ##   bitmap (.bmp)
  RT_ICON* = (3).ResourceType  ##   icon
  RT_MENU* = (4).ResourceType  ##   menu
  RT_DIALOG* = (5).ResourceType  ##   dialog window
  RT_STRING* = (6).ResourceType  ##   unicode string
  RT_FONTDIR* = (7).ResourceType ##   font directory
  RT_FONT* = (8).ResourceType  ##   font
  RT_ACCELERATOR* = (9).ResourceType  ##   hot keys
  RT_RCDATA* = (10).ResourceType  ##   data
  RT_MESSAGETABLE* = (11).ResourceType  ##   string table
  RT_GROUP_CURSOR* = (12).ResourceType  ##   cursor group
  RT_GROUP_ICON* = (14).ResourceType  ##   icon group
  RT_VERSION* = (16).ResourceType  ##   version information
  RT_DLGINCLUDE* = (17).ResourceType  ##   names of header files for dialogs (*.h) used by compiler
  RT_PLUGPLAY* = (19).ResourceType  ##   data determined by application
  RT_VXD* = (20).ResourceType  ##   vxd info
  RT_ANICURSOR* = (21).ResourceType  ##   animated cursor
  RT_ANIICON* = (22).ResourceType  ##   animated icon
  RT_HTML* = (23).ResourceType  ##   html page
  RT_MANIFEST* = (24).ResourceType  ##   manifest of Windows XP build
  RT_DLGINIT* = (240).ResourceType  ##   strings used for initiating some controls in dialogs
  RT_TOOLBAR* = (241).ResourceType  ##   configuration of toolbars

type
  IMAGE_RESOURCE_DIRECTORY* {.bycopy, importc, impdir_resourcesHdr.} = object
    Characteristics*: uint32
    TimeDateStamp*: uint32
    MajorVersion*: uint16
    MinorVersion*: uint16
    NumberOfNamedEntries*: uint16
    NumberOfIdEntries*: uint16

  Type_dir_resourcesh1* {.bycopy, impdir_resourcesHdr,
                          importc: "struct Type_dir_resourcesh1".} = object
    NameOffset* {.bitsize: 31.}: uint32
    NameIsString* {.bitsize: 1.}: uint32

  Union_dir_resourcesh1* {.union, bycopy, impdir_resourcesHdr,
                           importc: "union Union_dir_resourcesh1".} = object
    data*: Type_dir_resourcesh1
    Name*: uint32
    Id*: uint16

  Type_dir_resourcesh2* {.bycopy, impdir_resourcesHdr,
                          importc: "struct Type_dir_resourcesh2".} = object
    OffsetToDirectory* {.bitsize: 31.}: uint32
    DataIsDirectory* {.bitsize: 1.}: uint32

  Union_dir_resourcesh2* {.union, bycopy, impdir_resourcesHdr,
                           importc: "union Union_dir_resourcesh2".} = object
    OffsetToData*: uint32
    data*: Type_dir_resourcesh2

  IMAGE_RESOURCE_DIRECTORY_ENTRY* {.bycopy, importc, impdir_resourcesHdr.} = object
    u0*: Union_dir_resourcesh1
    u1*: Union_dir_resourcesh2

  IMAGE_RESOURCE_DATA_STRING* {.bycopy, importc, impdir_resourcesHdr.} = object
    Length*: uint16
    String*: array[1, cchar]

  IMAGE_RESOURCE_DATA_STRING_U* {.bycopy, importc, impdir_resourcesHdr.} = object
    Length*: uint16  ##   Number of Unicode characters
    String*: array[1, uint16]  ##   Number of Unicode characters

  
  IMAGE_RESOURCE_DATA_ENTRY* {.bycopy, importc, impdir_resourcesHdr.} = object
    OffsetToData*: uint32
    Size*: uint32
    CodePage*: uint32
    Reserved*: uint32

  VS_FIXEDFILEINFO* {.bycopy, importc, impdir_resourcesHdr.} = object
    dwSignature*: uint32
    dwStrucVersion*: uint32
    dwFileVersionMS*: uint32
    dwFileVersionLS*: uint32
    dwProductVersionMS*: uint32
    dwProductVersionLS*: uint32
    dwFileFlagsMask*: uint32
    dwFileFlags*: uint32
    dwFileOS*: uint32
    dwFileType*: uint32
    dwFileSubtype*: uint32
    dwFileDateMS*: uint32
    dwFileDateLS*: uint32

