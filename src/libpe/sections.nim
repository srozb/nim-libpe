{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros

macro defineEnum(typ: untyped): untyped =
  result = newNimNode(nnkStmtList)

  # Enum mapped to distinct cint
  result.add quote do:
    type `typ`* = distinct cint

  for i in ["+", "-", "*", "div", "mod", "shl", "shr", "or", "and", "xor", "<", "<=", "==", ">", ">="]:
    let
      ni = newIdentNode(i)
      typout = if i[0] in "<=>": newIdentNode("bool") else: typ # comparisons return bool
    if i[0] == '>': # cannot borrow `>` and `>=` from templates
      let
        nopp = if i.len == 2: newIdentNode("<=") else: newIdentNode("<")
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` = `nopp`(y, x)
        proc `ni`*(x: cint, y: `typ`): `typout` = `nopp`(y, x)
        proc `ni`*(x, y: `typ`): `typout` = `nopp`(y, x)
    else:
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` {.borrow.}
        proc `ni`*(x: cint, y: `typ`): `typout` {.borrow.}
        proc `ni`*(x, y: `typ`): `typout` {.borrow.}
    result.add quote do:
      proc `ni`*(x: `typ`, y: int): `typout` = `ni`(x, y.cint)
      proc `ni`*(x: int, y: `typ`): `typout` = `ni`(x.cint, y)

  let
    divop = newIdentNode("/")   # `/`()
    dlrop = newIdentNode("$")   # `$`()
    notop = newIdentNode("not") # `not`()
  result.add quote do:
    proc `divop`*(x, y: `typ`): `typ` = `typ`((x.float / y.float).cint)
    proc `divop`*(x: `typ`, y: cint): `typ` = `divop`(x, `typ`(y))
    proc `divop`*(x: cint, y: `typ`): `typ` = `divop`(`typ`(x), y)
    proc `divop`*(x: `typ`, y: int): `typ` = `divop`(x, y.cint)
    proc `divop`*(x: int, y: `typ`): `typ` = `divop`(x.cint, y)

    proc `dlrop`*(x: `typ`): string {.borrow.}
    proc `notop`*(x: `typ`): `typ` {.borrow.}


{.pragma: impsectionsHdr, header: "libpe/libpe/include/libpe/sections.h".}
{.experimental: "codeReordering".}
defineEnum(SectionCharacteristics)
const
  SECTION_NAME_SIZE* = 8
  IMAGE_SCN_TYPE_NO_PAD* = (0x00000008).SectionCharacteristics ## ```
                                                               ##   Obsolete. Replaced by IMAGE_SCN_ALIGN_1BYTES
                                                               ## ```
  IMAGE_SCN_CNT_CODE* = (0x00000020).SectionCharacteristics ## ```
                                                            ##   Obsolete. Replaced by IMAGE_SCN_ALIGN_1BYTES
                                                            ## ```
  IMAGE_SCN_CNT_INITIALIZED_DATA* = (0x00000040).SectionCharacteristics
  IMAGE_SCN_CNT_UNINITIALIZED_DATA* = (0x00000080).SectionCharacteristics
  IMAGE_SCN_LNK_OTHER* = (0x00000100).SectionCharacteristics ## ```
                                                             ##   Reserved.
                                                             ## ```
  IMAGE_SCN_LNK_INFO* = (0x00000200).SectionCharacteristics ## ```
                                                            ##   Valid only for object files.
                                                            ## ```
  IMAGE_SCN_LNK_REMOVE* = (0x00000800).SectionCharacteristics ## ```
                                                              ##   Valid only for object files.
                                                              ## ```
  IMAGE_SCN_LNK_COMDAT* = (0x00001000).SectionCharacteristics ## ```
                                                              ##   Valid only for object files.
                                                              ## ```
  IMAGE_SCN_NO_DEFER_SPEC_EXC* = (0x00004000).SectionCharacteristics ## ```
                                                                     ##   Valid only for object files.
                                                                     ## ```
  IMAGE_SCN_GPREL* = (0x00008000).SectionCharacteristics
  IMAGE_SCN_MEM_PURGEABLE* = (0x00020000).SectionCharacteristics ## ```
                                                                 ##   Reserved.
                                                                 ## ```
  IMAGE_SCN_MEM_LOCKED* = (0x00040000).SectionCharacteristics ## ```
                                                              ##   Reserved.
                                                              ## ```
  IMAGE_SCN_MEM_PRELOAD* = (0x00080000).SectionCharacteristics ## ```
                                                               ##   Reserved.
                                                               ## ```
  IMAGE_SCN_ALIGN_1BYTES* = (0x00100000).SectionCharacteristics ## ```
                                                                ##   Valid only for object files.
                                                                ## ```
  IMAGE_SCN_ALIGN_2BYTES* = (0x00200000).SectionCharacteristics ## ```
                                                                ##   Valid only for object files.
                                                                ## ```
  IMAGE_SCN_ALIGN_4BYTES* = (0x00300000).SectionCharacteristics ## ```
                                                                ##   Valid only for object files.
                                                                ## ```
  IMAGE_SCN_ALIGN_8BYTES* = (0x00400000).SectionCharacteristics ## ```
                                                                ##   Valid only for object files.
                                                                ## ```
  IMAGE_SCN_ALIGN_16BYTES* = (0x00500000).SectionCharacteristics ## ```
                                                                 ##   Valid only for object files.
                                                                 ## ```
  IMAGE_SCN_ALIGN_32BYTES* = (0x00600000).SectionCharacteristics ## ```
                                                                 ##   Valid only for object files.
                                                                 ## ```
  IMAGE_SCN_ALIGN_64BYTES* = (0x00700000).SectionCharacteristics ## ```
                                                                 ##   Valid only for object files.
                                                                 ## ```
  IMAGE_SCN_ALIGN_128BYTES* = (0x00800000).SectionCharacteristics ## ```
                                                                  ##   Valid only for object files.
                                                                  ## ```
  IMAGE_SCN_ALIGN_256BYTES* = (0x00900000).SectionCharacteristics ## ```
                                                                  ##   Valid only for object files.
                                                                  ## ```
  IMAGE_SCN_ALIGN_512BYTES* = (0x00A00000).SectionCharacteristics ## ```
                                                                  ##   Valid only for object files.
                                                                  ## ```
  IMAGE_SCN_ALIGN_1024BYTES* = (0x00B00000).SectionCharacteristics ## ```
                                                                   ##   Valid only for object files.
                                                                   ## ```
  IMAGE_SCN_ALIGN_2048BYTES* = (0x00C00000).SectionCharacteristics ## ```
                                                                   ##   Valid only for object files.
                                                                   ## ```
  IMAGE_SCN_ALIGN_4096BYTES* = (0x00D00000).SectionCharacteristics ## ```
                                                                   ##   Valid only for object files.
                                                                   ## ```
  IMAGE_SCN_ALIGN_8192BYTES* = (0x00E00000).SectionCharacteristics ## ```
                                                                   ##   Valid only for object files.
                                                                   ## ```
  IMAGE_SCN_LNK_NRELOC_OVFL* = (0x01000000).SectionCharacteristics ## ```
                                                                   ##   Valid only for object files.
                                                                   ## ```
  IMAGE_SCN_MEM_DISCARDABLE* = (0x02000000).SectionCharacteristics
  IMAGE_SCN_MEM_NOT_CACHED* = (0x04000000).SectionCharacteristics
  IMAGE_SCN_MEM_NOT_PAGED* = (0x08000000).SectionCharacteristics
  IMAGE_SCN_MEM_SHARED* = (0x10000000).SectionCharacteristics
  IMAGE_SCN_MEM_EXECUTE* = (0x20000000).SectionCharacteristics
  IMAGE_SCN_MEM_READ* = (0x40000000).SectionCharacteristics
  IMAGE_SCN_MEM_WRITE* = (-2147483648).SectionCharacteristics ## ```
                                                              ##   Same as 0x80000000
                                                              ## ```
type
  Union_sectionsh1* {.union, bycopy, impsectionsHdr,
                      importc: "union Union_sectionsh1".} = object ## ```
                                                                    ##   TODO: Should we use char instead?
                                                                    ## ```
    PhysicalAddress*: uint32 ## ```
                             ##   same value as next field
                             ## ```
    VirtualSize*: uint32     ## ```
                             ##   same value as next field
                             ## ```
  
  IMAGE_SECTION_HEADER* {.bycopy, importc, impsectionsHdr.} = object ## ```
                                                                      ##   Quoting pecoff_v8.docx: "Entries in the section table are numbered starting from one (1)".
                                                                      ## ```
    Name*: array[8, uint8]   ## ```
                             ##   TODO: Should we use char instead?
                             ## ```
    Misc*: Union_sectionsh1  ## ```
                             ##   TODO: Should we use char instead?
                             ## ```
    VirtualAddress*: uint32
    SizeOfRawData*: uint32
    PointerToRawData*: uint32
    PointerToRelocations*: uint32 ## ```
                                  ##   always zero in executables
                                  ## ```
    PointerToLinenumbers*: uint32 ## ```
                                  ##   deprecated
                                  ## ```
    NumberOfRelocations*: uint16 ## ```
                                 ##   deprecated
                                 ## ```
    NumberOfLinenumbers*: uint16 ## ```
                                 ##   deprecated
                                 ## ```
    Characteristics*: uint32 ## ```
                             ##   SectionCharacteristics
                             ## ```
  
{.pop.}
