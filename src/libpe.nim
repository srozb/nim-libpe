import std/memFiles

## For entropy
import tables
import math
##

import libpe/pe
import libpe/hdr_dos
import libpe/hdr_coff
import libpe/hdr_optional
import libpe/directories
import libpe/sections
import libpe/imports
import libpe/exports
import libpe/error
import libpe/hashes
import libpe/resources
import libpe/dir_resources
import libpe/dir_import

when defined(MacOsX):
  const libpePath = "/usr/local/opt/pev/lib/libpe.1.0.dylib"
elif defined(mingw):
  const libpePath = "libpe.dll"
elif defined(Windows):
  const libpePath = "libpe.dll"
  ## TODO: Linux

{.experimental: "codeReordering".}

{.pragma: imppeHdr, header: "pe.h".}
{.pragma: impError, header: "error.h".}
{.pragma: impresourcesHdr, header: "resources.h".}

var 
  mFile: MemFile
  peDirs: Directories
  peSects: Sections
  gExports: pe_exports_t
  gImports: pe_imports_t

proc `+`(a: pointer, s: Natural): pointer = cast[pointer](cast[int](a) + s)

converter ptrToPtrUint(a: pointer): ptr uint = cast[ptr uint](a)
converter ptrToPtrUint32(a: pointer): ptr uint32 = cast[ptr uint32](a)

proc pe_can_read*(ctx: ptr pe_ctx_t, `ptr`: pointer, size: uint): bool =
  let 
    pStart = cast[int](`ptr`)
    pEnd = pStart + size.int
  return pStart >= cast[int](ctx.map_addr) and pEnd <= cast[int](ctx.map_end)

proc pe_load_file_ext*(ctx: ptr pe_ctx_t, path: cstring, options: pe_options_e): pe_err_e =
  result = LIBPE_E_OK
  ctx.path = path
  mFile = memfiles.open($path, mode=fmReadWriteExisting)  # try return LIBPE_E_OPEN_FAILED
  # return LIBPE_E_NOT_A_FILE if not a file
  ctx.map_size = mFile.size.clong
  ctx.map_addr = mFile.mem  # return LIBPE_E_MMAP_FAILED if error
  ctx.map_end = ctx.map_addr + mFile.size
  #TODO:? madvise(ctx->map_addr, ctx->map_size, MADV_SEQUENTIAL);
  #TODO: OpenSSL_add_all_digests();

proc pe_load_file*(ctx: ptr pe_ctx_t, path: cstring): pe_err_e =
  return pe_load_file_ext(ctx, path, cast[pe_options_e](0))

proc pe_unload*(ctx: ptr pe_ctx_t): pe_err_e =
  if ctx.map_addr != mFile.mem:
      return LIBPE_E_MUNMAP_FAILED
  else:
      mFile.close()
  LIBPE_E_OK

proc pe_parse*(ctx: ptr pe_ctx_t): pe_err_e =
  result = LIBPE_E_OK
  ctx.pe.dos_hdr = cast[ptr IMAGE_DOS_HEADER](ctx.map_addr)
  if ctx.pe.dos_hdr.e_magic != MAGIC_MZ: return LIBPE_E_NOT_A_PE_FILE

  var signature_ptr: ptr uint32 = ctx.pe.dos_hdr + ctx.pe.dos_hdr.e_lfanew

  if not pe_can_read(ctx, signature_ptr, sizeof(pe_file_t.signature).uint): return LIBPE_E_INVALID_LFANEW

  ctx.pe.signature = signature_ptr[]
  if ctx.pe.signature != SIGNATURE_PE and ctx.pe.signature != SIGNATURE_NE: return LIBPE_E_INVALID_SIGNATURE

  ctx.pe.coff_hdr = cast[ptr IMAGE_COFF_HEADER](signature_ptr + sizeof(ctx.pe.signature))

  if not pe_can_read(ctx, ctx.pe.coff_hdr, sizeof(IMAGE_COFF_HEADER).uint): return LIBPE_E_MISSING_COFF_HEADER

  ctx.pe.num_sections = ctx.pe.coff_hdr.NumberOfSections

  ctx.pe.optional_hdr_ptr = ctx.pe.coff_hdr + sizeof(IMAGE_COFF_HEADER)
  ctx.pe.optional_hdr.`type` = cast[ptr uint16](ctx.pe.optional_hdr_ptr)[]

  case ctx.pe.optional_hdr.`type`:  # TODO: use template to avoid repetition
  of MAGIC_PE32.uint16:
    ctx.pe.optional_hdr.h_32 = cast[ptr IMAGE_OPTIONAL_HEADER_32](ctx.pe.optional_hdr_ptr)
    ctx.pe.optional_hdr.length = sizeof(IMAGE_OPTIONAL_HEADER_32).uint
    ctx.pe.num_directories = ctx.pe.optional_hdr.h_32.NumberOfRvaAndSizes
    ctx.pe.entrypoint = ctx.pe.optional_hdr.h_32.AddressOfEntryPoint
    ctx.pe.imagebase = ctx.pe.optional_hdr.h_32.ImageBase;
  of MAGIC_PE64.uint16:
    ctx.pe.optional_hdr.h_64 = cast[ptr IMAGE_OPTIONAL_HEADER_64](ctx.pe.optional_hdr_ptr)
    ctx.pe.optional_hdr.length = sizeof(IMAGE_OPTIONAL_HEADER_64).uint
    ctx.pe.num_directories = ctx.pe.optional_hdr.h_64.NumberOfRvaAndSizes;
    ctx.pe.entrypoint = ctx.pe.optional_hdr.h_64.AddressOfEntryPoint;
    ctx.pe.imagebase = ctx.pe.optional_hdr.h_64.ImageBase;
  else:
    return LIBPE_E_UNSUPPORTED_IMAGE

  if ctx.pe.num_directories > MAX_DIRECTORIES: return LIBPE_E_TOO_MANY_DIRECTORIES
  if ctx.pe.num_sections > MAX_SECTIONS: return LIBPE_E_TOO_MANY_SECTIONS

  ctx.pe.directories_ptr = ctx.pe.optional_hdr_ptr + ctx.pe.optional_hdr.length

  let sectionOffset = sizeof(ctx.pe.signature) + sizeof(IMAGE_COFF_HEADER) + ctx.pe.coff_hdr.SizeOfOptionalHeader.int
  ctx.pe.sections_ptr = signature_ptr + sectionOffset

  if ctx.pe.num_directories > 0:
    for i in 0..<ctx.pe.num_directories:
      let dirAddr = ctx.pe.directories_ptr + (i.int * sizeof(IMAGE_DATA_DIRECTORY))
      peDirs[i] = cast[ptr IMAGE_DATA_DIRECTORY](dirAddr)
    ctx.pe.directories = addr peDirs

  if ctx.pe.num_sections > 0:
    for i in 0..<ctx.pe.num_sections.Natural:
      let sectAddr = ctx.pe.sections_ptr + (i * sizeof(IMAGE_SECTION_HEADER))
      peSects[i] = cast[ptr IMAGE_SECTION_HEADER](sectAddr)
    ctx.pe.sections = addr peSects

proc pe_is_loaded*(ctx: ptr pe_ctx_t): bool = 
  cast[int](ctx.map_addr) >= 0 and ctx.map_size > 0
proc pe_is_pe*(ctx: ptr pe_ctx_t): bool = 
  ctx.pe.dos_hdr.e_magic == MAGIC_MZ and ctx.pe.signature == SIGNATURE_PE
proc pe_is_dll*(ctx: ptr pe_ctx_t): bool = 
  bool(ctx.pe.coff_hdr.Characteristics.ImageCharacteristics and IMAGE_FILE_DLL)
proc pe_filesize*(ctx: ptr pe_ctx_t): uint64 = ctx.map_size.uint64
proc pe_dos*(ctx: ptr pe_ctx_t): ptr IMAGE_DOS_HEADER = ctx.pe.dos_hdr
proc pe_coff*(ctx: ptr pe_ctx_t): ptr IMAGE_COFF_HEADER = ctx.pe.coff_hdr
proc pe_optional*(ctx: ptr pe_ctx_t): ptr IMAGE_OPTIONAL_HEADER = 
  addr ctx.pe.optional_hdr

proc pe_sections_count*(ctx: ptr pe_ctx_t): uint16 = ctx.pe.num_sections
proc pe_sections*(ctx: ptr pe_ctx_t): ptr Sections = ctx.pe.sections

proc pe_directories_count*(ctx: ptr pe_ctx_t): uint32 = ctx.pe.num_directories
proc pe_directories*(ctx: ptr pe_ctx_t): ptr Directories = ctx.pe.directories

iterator sections*(ctx: var pe_ctx_t): ptr IMAGE_SECTION_HEADER =
  let peSections = pe_sections(addr ctx)
  for i in 0..<pe_sections_count(addr ctx).Natural: 
    yield peSections[i]

iterator directories*(ctx: var pe_ctx_t): (ImageDirectoryEntry, ptr IMAGE_DATA_DIRECTORY) =
  for i in 0..<pe_directories_count(addr ctx).Natural:
    if ctx.pe.directories[i].Size == 0: continue
    yield (i.ImageDirectoryEntry, ctx.pe.directories[i])

proc pe_rva2section*(ctx: ptr pe_ctx_t, rva: uint64): ptr IMAGE_SECTION_HEADER =
  if rva == 0 or ctx.pe.num_sections == 0: return   # TODO: raise an exception or sth?
  for sect in ctx[].sections:
    if rva >= sect.VirtualAddress and rva <= sect.VirtualAddress + sect.Misc.VirtualSize:
      return sect

proc pe_rva2ofs*(ctx: ptr pe_ctx_t, rva: uint64): uint64 =
  if rva == 0 or ctx.pe.num_sections == 0: return 0
  for sect in ctx[].sections:
    var sectSize = sect.Misc.VirtualSize
    if sectSize == 0:
      sectSize = sect.SizeOfRawData
    if sect.VirtualAddress <= rva:
      if sect.VirtualAddress + sectSize > rva:
        result = rva - sect.VirtualAddress
        return result + sect.PointerToRawData
  if ctx.pe.num_sections == 1:  # Handle PE with a single section
    result = rva - ctx.pe.sections[0].VirtualAddress
    return result + ctx.pe.sections[0].PointerToRawData

proc pe_ofs2rva*(ctx: ptr pe_ctx_t, ofs: uint64): uint64 =
  if ofs == 0 or ctx.pe.num_sections == 0: return 0
  for sect in ctx[].sections:
    if sect.PointerToRawData <= ofs:
      if sect.PointerToRawData + sect.SizeOfRawData > ofs:
        result = ofs - sect.PointerToRawData
        return result + sect.VirtualAddress

proc pe_section_name*(ctx: ptr pe_ctx_t, section_hdr: ptr IMAGE_SECTION_HEADER,
                      out_name: var cstring, out_name_size: uint): cstring =
  # This function is really stupid but I'll leave it for compatibility
  out_name = section_hdr.Name
  result = out_name

proc pe_machine_type_name*(`type`: MachineType): cstring =
  result = "IMAGE_FILE_MACHINE_UNKNOWN".cstring
  type 
    Machine = tuple
      entryId: MachineType
      name: string

  const entries: seq[Machine] = @[  # TODO: Macro
    (IMAGE_FILE_MACHINE_AM33, "IMAGE_FILE_MACHINE_AM33"),
    (IMAGE_FILE_MACHINE_AMD64, "IMAGE_FILE_MACHINE_AMD64"),
    (IMAGE_FILE_MACHINE_ARM, "IMAGE_FILE_MACHINE_ARM"),
    (IMAGE_FILE_MACHINE_ARMV7, "IMAGE_FILE_MACHINE_ARMV7"),
    (IMAGE_FILE_MACHINE_CEE, "IMAGE_FILE_MACHINE_CEE"),
    (IMAGE_FILE_MACHINE_EBC, "IMAGE_FILE_MACHINE_EBC"),
    (IMAGE_FILE_MACHINE_I386, "IMAGE_FILE_MACHINE_I386"),
    (IMAGE_FILE_MACHINE_IA64, "IMAGE_FILE_MACHINE_IA64"),
    (IMAGE_FILE_MACHINE_M32R, "IMAGE_FILE_MACHINE_M32R"),
    (IMAGE_FILE_MACHINE_MIPS16, "IMAGE_FILE_MACHINE_MIPS16"),
    (IMAGE_FILE_MACHINE_MIPSFPU, "IMAGE_FILE_MACHINE_MIPSFPU"),
    (IMAGE_FILE_MACHINE_MIPSFPU16, "IMAGE_FILE_MACHINE_MIPSFPU16"),
    (IMAGE_FILE_MACHINE_POWERPC, "IMAGE_FILE_MACHINE_POWERPC"),
    (IMAGE_FILE_MACHINE_POWERPCFP, "IMAGE_FILE_MACHINE_POWERPCFP"),
    (IMAGE_FILE_MACHINE_R4000, "IMAGE_FILE_MACHINE_R4000"),
    (IMAGE_FILE_MACHINE_SH3, "IMAGE_FILE_MACHINE_SH3"),
    (IMAGE_FILE_MACHINE_SH3DSP, "IMAGE_FILE_MACHINE_SH3DSP"),
    (IMAGE_FILE_MACHINE_SH4, "IMAGE_FILE_MACHINE_SH4"),
    (IMAGE_FILE_MACHINE_SH5, "IMAGE_FILE_MACHINE_SH5"),
    (IMAGE_FILE_MACHINE_THUMB, "IMAGE_FILE_MACHINE_THUMB"),
    (IMAGE_FILE_MACHINE_WCEMIPSV2, "IMAGE_FILE_MACHINE_WCEMIPSV2")
  ]

  for e in entries:
    if e.entryId == `type`: return e.name.cstring

proc pe_image_characteristic_name*(characteristic: ImageCharacteristics): cstring =
  type 
    ImageCharacteristicsName = tuple
      entryId: ImageCharacteristics
      name: string

  const entries: seq[ImageCharacteristicsName] = @[
    (IMAGE_FILE_RELOCS_STRIPPED, "IMAGE_FILE_RELOCS_STRIPPED"),
    (IMAGE_FILE_EXECUTABLE_IMAGE, "IMAGE_FILE_EXECUTABLE_IMAGE"),
    (IMAGE_FILE_LINE_NUMS_STRIPPED, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
    (IMAGE_FILE_LOCAL_SYMS_STRIPPED, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
    (IMAGE_FILE_AGGRESSIVE_WS_TRIM, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"),
    (IMAGE_FILE_LARGE_ADDRESS_AWARE, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
    (IMAGE_FILE_RESERVED, "IMAGE_FILE_RESERVED"),
    (IMAGE_FILE_BYTES_REVERSED_LO, "IMAGE_FILE_BYTES_REVERSED_LO"),
    (IMAGE_FILE_32BIT_MACHINE, "IMAGE_FILE_32BIT_MACHINE"),
    (IMAGE_FILE_DEBUG_STRIPPED, "IMAGE_FILE_DEBUG_STRIPPED"),
    (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
    (IMAGE_FILE_NET_RUN_FROM_SWAP, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
    (IMAGE_FILE_SYSTEM, "IMAGE_FILE_SYSTEM"),
    (IMAGE_FILE_DLL, "IMAGE_FILE_DLL"),
    (IMAGE_FILE_UP_SYSTEM_ONLY, "IMAGE_FILE_UP_SYSTEM_ONLY"),
    (IMAGE_FILE_BYTES_REVERSED_HI, "IMAGE_FILE_BYTES_REVERSED_HI")
  ]

  for e in entries:
    if e.entryId == characteristic: return e.name.cstring

proc pe_image_dllcharacteristic_name*(characteristic: ImageDllCharacteristics): cstring =
  type 
    ImageDllCharacteristicsName = tuple
      entryId: ImageDllCharacteristics
      name: string

  const entries: seq[ImageDllCharacteristicsName] = @[
    (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
    (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
    (IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
    (IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"),
    (IMAGE_DLLCHARACTERISTICS_NO_SEH, "IMAGE_DLLCHARACTERISTICS_NO_SEH"),
    (IMAGE_DLLCHARACTERISTICS_NO_BIND, "IMAGE_DLLCHARACTERISTICS_NO_BIND"),
    (IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"),
    (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE")
  ]

  for e in entries:
    if e.entryId == characteristic: return e.name.cstring

proc pe_windows_subsystem_name*(subsystem: WindowsSubsystem): cstring =
  result = "IMAGE_SUBSYSTEM_UNKNOWN".cstring
  type 
    WindowsSubsystemName = tuple
      entryId: WindowsSubsystem
      name: string

  const entries: seq[WindowsSubsystemName] = @[
    (IMAGE_SUBSYSTEM_NATIVE, "IMAGE_SUBSYSTEM_NATIVE"),
    (IMAGE_SUBSYSTEM_WINDOWS_GUI, "IMAGE_SUBSYSTEM_WINDOWS_GUI"),
    (IMAGE_SUBSYSTEM_WINDOWS_CUI, "IMAGE_SUBSYSTEM_WINDOWS_CUI"),
    (IMAGE_SUBSYSTEM_OS2_CUI, "IMAGE_SUBSYSTEM_OS2_CUI"),
    (IMAGE_SUBSYSTEM_POSIX_CUI, "IMAGE_SUBSYSTEM_POSIX_CUI"),
    (IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"),
    (IMAGE_SUBSYSTEM_EFI_APPLICATION, "IMAGE_SUBSYSTEM_EFI_APPLICATION"),
    (IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"),
    (IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"),
    (IMAGE_SUBSYSTEM_EFI_ROM, "IMAGE_SUBSYSTEM_EFI_ROM"),
    (IMAGE_SUBSYSTEM_XBOX, "IMAGE_SUBSYSTEM_XBOX"),
    (IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION")
  ]

  for e in entries:
    if e.entryId == subsystem: return e.name.cstring

proc pe_directory_name*(entry: ImageDirectoryEntry): cstring =
  type 
    ImageDirectoryEntryName = tuple
      entryId: ImageDirectoryEntry
      name: string

  const entries: seq[ImageDirectoryEntryName] = @[
    (IMAGE_DIRECTORY_ENTRY_EXPORT, "IMAGE_DIRECTORY_ENTRY_EXPORT"),
    (IMAGE_DIRECTORY_ENTRY_IMPORT, "IMAGE_DIRECTORY_ENTRY_IMPORT"),
    (IMAGE_DIRECTORY_ENTRY_RESOURCE, "IMAGE_DIRECTORY_ENTRY_RESOURCE"),
    (IMAGE_DIRECTORY_ENTRY_EXCEPTION, "IMAGE_DIRECTORY_ENTRY_EXCEPTION"),
    (IMAGE_DIRECTORY_ENTRY_SECURITY, "IMAGE_DIRECTORY_ENTRY_SECURITY"),
    (IMAGE_DIRECTORY_ENTRY_BASERELOC, "IMAGE_DIRECTORY_ENTRY_BASERELOC"),
    (IMAGE_DIRECTORY_ENTRY_DEBUG, "IMAGE_DIRECTORY_ENTRY_DEBUG"),
    (IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"),
    (IMAGE_DIRECTORY_ENTRY_GLOBALPTR, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"),
    (IMAGE_DIRECTORY_ENTRY_TLS, "IMAGE_DIRECTORY_ENTRY_TLS"),
    (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"),
    (IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"),
    (IMAGE_DIRECTORY_ENTRY_IAT, "IMAGE_DIRECTORY_ENTRY_IAT"),
    (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"),
    (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"),
    (IMAGE_DIRECTORY_RESERVED, "IMAGE_DIRECTORY_RESERVED")
  ]

  for e in entries:
    if e.entryId == entry: return e.name.cstring

proc pe_section_characteristic_name*(characteristic: SectionCharacteristics): cstring =
  type 
    SectionCharacteristicsName = tuple
      entryId: SectionCharacteristics
      name: string

  const entries: seq[SectionCharacteristicsName] = @[
    (IMAGE_SCN_TYPE_NO_PAD, "IMAGE_SCN_TYPE_NO_PAD"),
    (IMAGE_SCN_CNT_CODE, "IMAGE_SCN_CNT_CODE"),
    (IMAGE_SCN_CNT_INITIALIZED_DATA, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
    (IMAGE_SCN_CNT_UNINITIALIZED_DATA, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
    (IMAGE_SCN_LNK_OTHER, "IMAGE_SCN_LNK_OTHER"),
    (IMAGE_SCN_LNK_INFO, "IMAGE_SCN_LNK_INFO"),
    (IMAGE_SCN_LNK_REMOVE, "IMAGE_SCN_LNK_REMOVE"),
    (IMAGE_SCN_LNK_COMDAT, "IMAGE_SCN_LNK_COMDAT"),
    (IMAGE_SCN_NO_DEFER_SPEC_EXC, "IMAGE_SCN_NO_DEFER_SPEC_EXC"),
    (IMAGE_SCN_GPREL, "IMAGE_SCN_GPREL"),
    (IMAGE_SCN_MEM_PURGEABLE, "IMAGE_SCN_MEM_PURGEABLE"),
    (IMAGE_SCN_MEM_LOCKED, "IMAGE_SCN_MEM_LOCKED"),
    (IMAGE_SCN_MEM_PRELOAD, "IMAGE_SCN_MEM_PRELOAD"),
    (IMAGE_SCN_ALIGN_1BYTES, "IMAGE_SCN_ALIGN_1BYTES"),
    (IMAGE_SCN_ALIGN_2BYTES, "IMAGE_SCN_ALIGN_2BYTES"),
    (IMAGE_SCN_ALIGN_4BYTES, "IMAGE_SCN_ALIGN_4BYTES"),
    (IMAGE_SCN_ALIGN_8BYTES, "IMAGE_SCN_ALIGN_8BYTES"),
    (IMAGE_SCN_ALIGN_16BYTES, "IMAGE_SCN_ALIGN_16BYTES"),
    (IMAGE_SCN_ALIGN_32BYTES, "IMAGE_SCN_ALIGN_32BYTES"),
    (IMAGE_SCN_ALIGN_64BYTES, "IMAGE_SCN_ALIGN_64BYTES"),
    (IMAGE_SCN_ALIGN_128BYTES, "IMAGE_SCN_ALIGN_128BYTES"),
    (IMAGE_SCN_ALIGN_256BYTES, "IMAGE_SCN_ALIGN_256BYTES"),
    (IMAGE_SCN_ALIGN_512BYTES, "IMAGE_SCN_ALIGN_512BYTES"),
    (IMAGE_SCN_ALIGN_1024BYTES, "IMAGE_SCN_ALIGN_1024BYTES"),
    (IMAGE_SCN_ALIGN_2048BYTES, "IMAGE_SCN_ALIGN_2048BYTES"),
    (IMAGE_SCN_ALIGN_4096BYTES, "IMAGE_SCN_ALIGN_4096BYTES"),
    (IMAGE_SCN_ALIGN_8192BYTES, "IMAGE_SCN_ALIGN_8192BYTES"),
    (IMAGE_SCN_LNK_NRELOC_OVFL, "IMAGE_SCN_LNK_NRELOC_OVFL"),
    (IMAGE_SCN_MEM_DISCARDABLE, "IMAGE_SCN_MEM_DISCARDABLE"),
    (IMAGE_SCN_MEM_NOT_CACHED, "IMAGE_SCN_MEM_NOT_CACHED"),
    (IMAGE_SCN_MEM_NOT_PAGED, "IMAGE_SCN_MEM_NOT_PAGED"),
    (IMAGE_SCN_MEM_SHARED, "IMAGE_SCN_MEM_SHARED"),
    (IMAGE_SCN_MEM_EXECUTE, "IMAGE_SCN_MEM_EXECUTE"),
    (IMAGE_SCN_MEM_READ, "IMAGE_SCN_MEM_READ"),
    (IMAGE_SCN_MEM_WRITE, "IMAGE_SCN_MEM_WRITE")
  ]

  for e in entries:
    if e.entryId == characteristic: return e.name.cstring

proc pe_directory_by_entry*(ctx: ptr pe_ctx_t, entry: ImageDirectoryEntry): ptr IMAGE_DATA_DIRECTORY =
  for dir in ctx[].directories:
    if dir[0] == entry: return dir[1]

proc pe_section_by_name*(ctx: ptr pe_ctx_t, section_name: cstring): ptr IMAGE_SECTION_HEADER =
  for sect in ctx[].sections:
    if sect.Name == section_name: return sect

proc pe_exports*(ctx: ptr pe_ctx_t): ptr pe_exports_t =  # CHECK: ensure cache is working
  if ctx.cached_data.exports != nil: return ctx.cached_data.exports
  gExports.err = LIBPE_E_OK

  let dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT)
  if dir.isNil: return addr gExports # means no exports present

  let va = dir.VirtualAddress
  if va == 0: return addr gExports

  var ofs = pe_rva2ofs(ctx, va)
  var exp = cast[ptr IMAGE_EXPORT_DIRECTORY](ctx.map_addr + ofs)

  if not pe_can_read(ctx, exp, sizeof(IMAGE_EXPORT_DIRECTORY).uint): 
    gExports.err = LIBPE_E_EXPORTS_CANT_READ_DIR
    return addr gExports

  ofs = pe_rva2ofs(ctx, exp.Name)
  let name_ptr = ctx.map_addr + ofs
  if not pe_can_read(ctx, name_ptr, 1):
    gExports.err = LIBPE_E_EXPORTS_CANT_READ_RVA
    return addr gExports

  gExports.name = cast[cstring](name_ptr)
  let ordinal_base = exp[].Base

  ofs = pe_rva2ofs(ctx, exp.AddressOfNames)
  let rva_ptr = ctx.map_addr + ofs
  if not pe_can_read(ctx, rva_ptr, sizeof(uint32).uint):
    gExports.err = LIBPE_E_EXPORTS_CANT_READ_RVA
    return addr gExports

  gExports.functions_count = exp.NumberOfFunctions

  var expFuncs = newSeq[pe_exported_function_t](exp.NumberOfFunctions)
  gExports.functions = cast[ptr UncheckedArray[pe_exported_function_t]](addr expFuncs[0])
  # (ordinal: 0, name: nil, fwd_name: nil, address: 0)

  let offset_to_AddressOfFunctions = pe_rva2ofs(ctx, exp.AddressOfFunctions)
  let offset_to_AddressOfNames = pe_rva2ofs(ctx, exp.AddressOfNames)
  let offset_to_AddressOfNameOrdinals = pe_rva2ofs(ctx, exp.AddressOfNameOrdinals)

  var offsets_to_Names = newSeq[ptr uint64](exp.NumberOfFunctions)  # or maybe pointer

  for i in 0..<exp.NumberOfNames:
    let entry_ordinal_list_ptr = offset_to_AddressOfNameOrdinals + sizeof(uint16).uint * i
    let entry_ordinal_list = ctx.map_addr + entry_ordinal_list_ptr  # todo: entry_ord_l -> ordinal

    if not pe_can_read(ctx, entry_ordinal_list, sizeof(uint16).uint):
      discard  # TODO: raise exception 

    let ordinal = cast[ptr uint16](entry_ordinal_list)[]
    let entry_name_list_ptr = offset_to_AddressOfNames + sizeof(uint32).uint * i
    let entry_name_list = ctx.map_addr + entry_name_list_ptr

    if not pe_can_read(ctx, entry_name_list, sizeof(uint32).uint):
      discard  # TODO: raise exception

    let entry_name_rva = cast[ptr uint32](entry_name_list)[]
    let entry_name_ofs = pe_rva2ofs(ctx, entry_name_rva.uint64)

    if ordinal.int < exp.NumberOfFunctions.int:
      offsets_to_Names[ordinal] = cast[ptr uint64](entry_name_ofs)

  for i in 0..<exp.NumberOfFunctions:
    let entry_ordinal_list_ptr = offset_to_AddressOfFunctions + sizeof(uint32).uint * i
    let entry_va_list = ctx.map_addr + entry_ordinal_list_ptr  # todo: entry_ord_l -> ordinal

    if not pe_can_read(ctx, entry_va_list, sizeof(uint32).uint):
      break  # TODO: raise exception 

    let entry_va = cast[ptr uint32](entry_va_list)[]
    let entry_name_ofs = offsets_to_Names[i]

    var fname: cstring

    if cast[uint](entry_name_ofs) != 0:
      let entry_name = ctx.map_addr + cast[uint](entry_name_ofs)  # Check
      if not pe_can_read(ctx, entry_name, 1): break

      fname = cast[cstring](entry_name)

    gExports.functions[i].ordinal = ordinal_base + i;
    gExports.functions[i].address = entry_va;
    gExports.functions[i].name = fname

  # TODO: Cache
  return addr gExports

proc get_dll_count*(ctx: ptr pe_ctx_t): uint32 =
  let dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT)
  if dir.isNil: return

  let va = dir.VirtualAddress
  if va == 0: return 

  var ofs = pe_rva2ofs(ctx, va)

  while true:
    let id = cast[ptr IMAGE_IMPORT_DESCRIPTOR](ctx.map_addr + ofs)
    if not pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR).uint): return
    if id.u1.OriginalFirstThunk == 0 and id.FirstThunk == 0: break
    ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR).uint64

    let aux = ofs
    ofs = pe_rva2ofs(ctx, id.Name)
    if ofs == 0: break

    ofs = pe_rva2ofs(ctx, (if id.u1.OriginalFirstThunk != 0: id.u1.OriginalFirstThunk else: id.FirstThunk))
    if ofs == 0: break

    result.inc
    ofs = aux

proc get_functions_count*(ctx: ptr pe_ctx_t, offset: uint64): uint32 =
  var ofs = offset

  while true:
    case ctx.pe.optional_hdr.`type`:
    of MAGIC_PE32.uint16:
      let thunk = cast[ptr IMAGE_THUNK_DATA32](ctx.map_addr + ofs)
      if not pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32).uint): return
      let thunk_type = cast[ptr uint32](thunk)[]
      if thunk_type == 0: return
      let is_ordinal = (thunk_type and IMAGE_ORDINAL_FLAG32.uint32) != 0
      if not is_ordinal:
        let imp_ofs = pe_rva2ofs(ctx, thunk.u1.AddressOfData)
        let imp_name = cast[ptr IMAGE_IMPORT_BY_NAME](ctx.map_addr + imp_ofs)
        if not pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME).uint): return
      ofs += sizeof(IMAGE_THUNK_DATA32).uint
      # break  # why is this here?
    of MAGIC_PE64.uint16:
      let thunk = cast[ptr IMAGE_THUNK_DATA64](ctx.map_addr + ofs)
      if not pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64).uint): return
      let thunk_type = cast[ptr uint64](thunk)[]
      if thunk_type == 0: return
      let is_ordinal = (thunk_type and IMAGE_ORDINAL_FLAG32.uint64) != 0
      if not is_ordinal:
        let imp_ofs = pe_rva2ofs(ctx, thunk.u1.AddressOfData)
        let imp_name = cast[ptr IMAGE_IMPORT_BY_NAME](ctx.map_addr + imp_ofs)
        if not pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME).uint): return
      ofs += sizeof(IMAGE_THUNK_DATA64).uint
      # break  # why is this here?
    else:
      discard  # TODO: raise exception
    result.inc

proc parse_imported_functions*(ctx: ptr pe_ctx_t, imported_dll: ptr pe_imported_dll_t, offset: uint64): pe_err_e =
  imported_dll.err = LIBPE_E_OK
  imported_dll.functions_count = get_functions_count(ctx, offset)  # Malloc? gImports.dlls.imported_dll.functions_count

  var 
    fname: cstring
    is_ordinal: bool
    ordinal: uint16
    hint: uint16
    ofs = offset
    functions = newSeq[pe_imported_function_t](imported_dll.functions_count)

  imported_dll.functions = cast[ptr UncheckedArray[pe_imported_function_t]](addr functions[0])

  for i in 0..<imported_dll.functions_count:
    case ctx.pe.optional_hdr.`type`:
    of MAGIC_PE32.uint16:
      let thunk = cast[ptr IMAGE_THUNK_DATA32](ctx.map_addr + ofs)
      if not pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA32).uint):
        imported_dll.err = LIBPE_E_INVALID_THUNK
        return imported_dll.err
      let thunk_type = cast[ptr uint32](thunk)[]
      if thunk_type == 0: 
        imported_dll.err = LIBPE_E_INVALID_THUNK
        return LIBPE_E_INVALID_THUNK
      is_ordinal = (thunk_type and IMAGE_ORDINAL_FLAG32.uint) != 0
      if is_ordinal: 
        hint = 0
        ordinal = ((thunk.u1.Ordinal and not IMAGE_ORDINAL_FLAG32) and 0xffff).uint16
      else:
        let imp_ofs = pe_rva2ofs(ctx, thunk.u1.AddressOfData)
        let imp_name = cast[ptr IMAGE_IMPORT_BY_NAME](ctx.map_addr + imp_ofs)
        if not pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME).uint):
          imported_dll.err = LIBPE_E_ALLOCATION_FAILURE
          return imported_dll.err
        hint = imp_name.Hint
        ordinal = 0
        fname = imp_name.Name
      ofs += sizeof(IMAGE_THUNK_DATA32).uint
      # break
    of MAGIC_PE64.uint16:
      let thunk = cast[ptr IMAGE_THUNK_DATA64](ctx.map_addr + ofs)
      if not pe_can_read(ctx, thunk, sizeof(IMAGE_THUNK_DATA64).uint):
        imported_dll.err = LIBPE_E_INVALID_THUNK
        return imported_dll.err
      let thunk_type = cast[ptr uint64](thunk)[]
      if thunk_type == 0: 
        imported_dll.err = LIBPE_E_INVALID_THUNK
        return LIBPE_E_INVALID_THUNK
      is_ordinal = (thunk_type and IMAGE_ORDINAL_FLAG64.uint) != 0
      if is_ordinal: 
        hint = 0
        ordinal = ((thunk.u1.Ordinal and not IMAGE_ORDINAL_FLAG64) and 0xffff).uint16
      else:
        let imp_ofs = pe_rva2ofs(ctx, thunk.u1.AddressOfData)
        let imp_name = cast[ptr IMAGE_IMPORT_BY_NAME](ctx.map_addr + imp_ofs)
        if not pe_can_read(ctx, imp_name, sizeof(IMAGE_IMPORT_BY_NAME).uint):
          imported_dll.err = LIBPE_E_ALLOCATION_FAILURE
          return imported_dll.err
        hint = imp_name.Hint
        ordinal = 0
        fname = imp_name.Name
      ofs += sizeof(IMAGE_THUNK_DATA64).uint
      # break
    else:
      discard  # TODO: raise exception

    imported_dll.functions[i].hint = hint
    imported_dll.functions[i].ordinal = ordinal

    if not is_ordinal: imported_dll.functions[i].name = fname
    else: imported_dll.functions[i].name = ""  # so the name is never nil

proc pe_imports*(ctx: ptr pe_ctx_t): ptr pe_imports_t =
  if ctx.cached_data.imports != nil: return ctx.cached_data.imports
  gImports.err = LIBPE_E_OK

  gImports.dll_count = get_dll_count(ctx)
  if gImports.dll_count == 0: return addr gImports

  var gImportedDlls = newSeq[pe_imported_dll_t](gImports.dll_count)
  gImports.dlls = cast[ptr UncheckedArray[pe_imported_dll_t]](addr gImportedDlls[0])

  let dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_IMPORT)
  if dir.isNil: return addr gImports # means no exports present

  let va = dir.VirtualAddress
  if va == 0: return addr gImports

  var ofs = pe_rva2ofs(ctx, va)

  for i in 0..<gImports.dll_count:
    let id = cast[ptr IMAGE_IMPORT_DESCRIPTOR](ctx.map_addr + ofs)
    if not pe_can_read(ctx, id, sizeof(IMAGE_IMPORT_DESCRIPTOR).uint): break

    if id.u1.OriginalFirstThunk == 0 and id.FirstThunk == 0: break
    ofs += sizeof(IMAGE_IMPORT_DESCRIPTOR).uint
    let aux = ofs

    ofs = pe_rva2ofs(ctx, id.Name)
    if ofs == 0: break
    
    let dll_name_ptr = ctx.map_addr + ofs
    if not pe_can_read(ctx, dll_name_ptr, 1): break

    gImportedDlls[i].name = cast[cstring](dll_name_ptr)
    
    ofs = pe_rva2ofs(ctx, (if id.u1.OriginalFirstThunk != 0: id.u1.OriginalFirstThunk else: id.FirstThunk))

    if ofs == 0: break

    let parse_err = parse_imported_functions(ctx, addr gImportedDlls[i], ofs)
    if not parse_err == LIBPE_E_OK:
      gImports.err = parse_err
      return addr gImports

    ofs = aux

  return addr gImports
  # TODO: Cache
  
proc pe_calculate_entropy_file*(ctx: ptr pe_ctx_t): cdouble =
  let filesize = pe_filesize(ctx)
  var t = initCountTable[char]()
  for i in 0..<filesize:
    t.inc(cast[ptr char](ctx.map_addr + i)[])
  for x in t.values: result -= x/filesize.int * log2(x/filesize.int)


{.push dynlib: libpePath.}


  # Hash
proc pe_hash_recommended_size*(): uint {.importc, cdecl, imppeHdr.}  ##   Hash functions
proc pe_hash_raw_data*(output: cstring, output_size: uint, alg_name: cstring,
                       data: ptr uint8, data_size: uint): bool {.importc,
    cdecl, imppeHdr.}
proc pe_get_headers_hashes*(ctx: ptr pe_ctx_t): ptr pe_hash_headers_t {.importc,
    cdecl, imppeHdr.}
proc pe_get_sections_hash*(ctx: ptr pe_ctx_t): ptr pe_hash_sections_t {.importc,
    cdecl, imppeHdr.}
proc pe_get_file_hash*(ctx: ptr pe_ctx_t): ptr pe_hash_t {.importc, cdecl,
    imppeHdr.}
proc pe_imphash*(ctx: ptr pe_ctx_t, flavor: pe_imphash_flavor_e): cstring {.
    importc, cdecl, imppeHdr.}

  # Misc
proc pe_fpu_trick*(ctx: ptr pe_ctx_t): bool {.importc, cdecl, imppeHdr.}
proc pe_get_cpl_analysis*(ctx: ptr pe_ctx_t): cint {.importc, cdecl, imppeHdr.}
proc pe_has_fake_entrypoint*(ctx: ptr pe_ctx_t): cint {.importc, cdecl, imppeHdr.}
proc pe_get_tls_callback*(ctx: ptr pe_ctx_t): cint {.importc, cdecl, imppeHdr.}
proc pe_error_msg*(error: pe_err_e): cstring {.importc, cdecl, impError.}
proc pe_error_print*(stream: File; error: pe_err_e) {.importc, impError.}

  # Resources
proc pe_resources*(ctx: ptr pe_ctx_t): ptr pe_resources_t {.importc, cdecl,
    imppeHdr.}
proc pe_resource_entry_info_lookup*(name_offset: uint32): ptr pe_resource_entry_info_t {.
    importc, cdecl, impresourcesHdr.}
proc pe_resource_search_nodes*(result: ptr pe_resource_node_search_result_t;
                               node: ptr pe_resource_node_t;
                               predicate: pe_resource_node_predicate_fn) {.
    importc, cdecl, impresourcesHdr.}
proc pe_resources_dealloc_node_search_result*(
    result: ptr pe_resource_node_search_result_t) {.importc, cdecl,
    impresourcesHdr.}
proc pe_resource_root_node*(node: ptr pe_resource_node_t): ptr pe_resource_node_t {.
    importc, cdecl, impresourcesHdr.}
proc pe_resource_last_child_node*(parent_node: ptr pe_resource_node_t): ptr pe_resource_node_t {.
    importc, cdecl, impresourcesHdr.}
proc pe_resource_find_node_by_type_and_level*(node: ptr pe_resource_node_t;
    `type`: pe_resource_node_type_e; dirLevel: uint32): ptr pe_resource_node_t {.
    importc, cdecl, impresourcesHdr.}
proc pe_resource_find_parent_node_by_type_and_level*(
    node: ptr pe_resource_node_t; `type`: pe_resource_node_type_e;
    dirLevel: uint32): ptr pe_resource_node_t {.importc, cdecl, impresourcesHdr.}
proc pe_resource_parse_string_u*(ctx: ptr pe_ctx_t; output: cstring;
                                 output_size: uint; data_string_ptr: ptr IMAGE_RESOURCE_DATA_STRING_U): cstring {.
    importc, cdecl, impresourcesHdr.}

{.pop.}







