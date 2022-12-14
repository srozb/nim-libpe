import memFiles
import system

import libpe/pe
import libpe/globals
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
import libpe/utils

# Entropy
import tables
import math

# Hashes
import hashlib/rhash/[md5,sha1,sha256]
import libfuzzy/ssdeep

proc pe_can_read*(ctx: ptr pe_ctx_t, `ptr`: pointer, size: uint): bool =
  ## Determine if the given memory offset is within the mapped PE file.
  let 
    pStart = cast[int](`ptr`)
    pEnd = pStart + size.int
  return pStart >= cast[int](ctx.map_addr) and pEnd <= cast[int](ctx.map_end)

proc pe_load_file_ext*(ctx: ptr pe_ctx_t, path: cstring, options: pe_options_e): pe_err_e =
  result = LIBPE_E_OK
  ctx.path = path
  mFile = memfiles.open($path, mode=fmRead)  # try return LIBPE_E_OPEN_FAILED
  # return LIBPE_E_NOT_A_FILE if not a file
  ctx.map_size = mFile.size.clong
  ctx.map_addr = mFile.mem  # return LIBPE_E_MMAP_FAILED if error
  ctx.map_end = ctx.map_addr + mFile.size
  #TODO:? madvise(ctx->map_addr, ctx->map_size, MADV_SEQUENTIAL);
  #TODO: OpenSSL_add_all_digests();

proc pe_load_file*(ctx: ptr pe_ctx_t, path: cstring): pe_err_e =
  return pe_load_file_ext(ctx, path, cast[pe_options_e](0))

proc pe_unload*(ctx: ptr pe_ctx_t): pe_err_e =
  ## Unload the memfile from memory as well as clear all the data structures.
  if ctx.map_addr != mFile.mem: return LIBPE_E_MUNMAP_FAILED
  mFile.close()
  deallocateAll()
  ctx[] = pe_ctx_t()
  LIBPE_E_OK

proc pe_parse*(ctx: ptr pe_ctx_t): pe_err_e =
  result = LIBPE_E_OK
  ctx.cached_data = gCachedData
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
        return rva - sect.VirtualAddress + sect.PointerToRawData
  if ctx.pe.num_sections == 1:  # Handle PE with a single section
    return rva - ctx.pe.sections[0].VirtualAddress + ctx.pe.sections[0].PointerToRawData

proc pe_ofs2rva*(ctx: ptr pe_ctx_t, ofs: uint64): uint64 =
  if ofs == 0 or ctx.pe.num_sections == 0: return 0
  for sect in ctx[].sections:
    if sect.PointerToRawData <= ofs:
      if sect.PointerToRawData + sect.SizeOfRawData > ofs:
        result = ofs - sect.PointerToRawData
        return result + sect.VirtualAddress

proc pe_section_name*(ctx: ptr pe_ctx_t, section_hdr: ptr IMAGE_SECTION_HEADER,
                      out_name: var cstring, out_name_size: uint): cstring =
  var outname = newString(8)
  outname = $cast[cstring](section_hdr.Name)
  # out_name = section_hdr.Name
  result = outname.cstring

proc pe_directory_by_entry*(ctx: ptr pe_ctx_t, entry: ImageDirectoryEntry): ptr IMAGE_DATA_DIRECTORY =
  for dir in ctx[].directories:
    if dir[0] == entry: return dir[1]

proc pe_section_by_name*(ctx: ptr pe_ctx_t, section_name: cstring): ptr IMAGE_SECTION_HEADER =
  for sect in ctx[].sections:
    if sect[].getName() == $section_name: return sect

proc pe_exports*(ctx: ptr pe_ctx_t): ptr pe_exports_t =  # CHECK: ensure cache is working
  ## Parse the PE exports table.
  if ctx.cached_data.exports != nil: return ctx.cached_data.exports
  gExports.err = LIBPE_E_OK

  let dir = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_EXPORT)
  if dir.isNil: return addr gExports # means no exports present

  let va = dir.VirtualAddress
  if va == 0: return addr gExports
  # echo "va: " & $va
  # echo "ofs: " & $pe_rva2ofs(ctx, va)
  var ofs = pe_rva2ofs(ctx, va)  # BUG for sample: 9525c704ae4ae5ef8a21b705c1df4516031a96e0e0c439bfec47540f73509c97
  var exp = cast[ptr IMAGE_EXPORT_DIRECTORY](ctx.map_addr + ofs)
  if exp[].NumberOfFunctions > 10000:  # BUG
    return addr gExports

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

  if exp.NumberOfFunctions == 0: return addr gExports  # No exports present

  gExports.functions_count = exp.NumberOfFunctions

  gExportedFuncs.setLen exp.NumberOfFunctions
  gExports.functions = cast[ptr UncheckedArray[pe_exported_function_t]](addr gExportedFuncs[0])

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
  ## Returns the imported DLLs count.
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
  ## Returns the imported function count.
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
  ## Parse imported functions details. This is called by `pe_imports`.
  imported_dll.err = LIBPE_E_OK
  imported_dll.functions_count = get_functions_count(ctx, offset)  # Malloc? gImports.dlls.imported_dll.functions_count

  var
    is_ordinal: bool
    ordinal: uint16
    hint: uint16
    ofs = offset
    functions = newSeq[pe_imported_function_t](imported_dll.functions_count)
  
  gImportedFunctions.add(functions)
  let nIdx = gImportedFunctions.len - 1

  imported_dll.functions = cast[ptr UncheckedArray[pe_imported_function_t]](addr gImportedFunctions[nIdx][0])

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
        gImportedFunctionsName.add(imp_name.getName())
      ofs += sizeof(IMAGE_THUNK_DATA32).uint
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
        gImportedFunctionsName.add(imp_name.getName())
      ofs += sizeof(IMAGE_THUNK_DATA64).uint
    else:
      discard  # TODO: raise exception

    imported_dll.functions[i].hint = hint
    imported_dll.functions[i].ordinal = ordinal

    if not is_ordinal: imported_dll.functions[i].name = gImportedFunctionsName[gImportedFunctionsName.len-1].cstring
    else: imported_dll.functions[i].name = ""  # so the name is never nil

proc pe_imports*(ctx: ptr pe_ctx_t): ptr pe_imports_t =
  ## Parse the PE import table.
  if ctx.cached_data.imports != nil: return ctx.cached_data.imports
  gImports.err = LIBPE_E_OK

  gImports.dll_count = get_dll_count(ctx)
  if gImports.dll_count == 0: return addr gImports

  # var gImportedDlls = newSeq[pe_imported_dll_t](gImports.dll_count)
  gImportedDlls.setLen gImports.dll_count
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
  ## Count file entropy.
  let filesize = pe_filesize(ctx)
  var t = initCountTable[char]()
  for i in 0..<filesize:
    t.inc(cast[ptr char](ctx.map_addr + i)[])
  for x in t.values: result -= x/filesize.int * log2(x/filesize.int)

proc pe_hash_recommended_size*(): uint = 148.uint
  ## Hardcoded value that should suffice to store every hash output.

proc pe_hash_raw_data*(output: cstring, output_size: var uint, alg_name: cstring,
                       data: ptr uint8, data_size: uint): bool =
  ## Actually hash the data using specified hashing algorithm.
  ## Output will be copied to the `output` variable. Be sure to allocate enough
  ## data.
  result = true
  var hashOut = newString(pe_hash_recommended_size())
  case $alg_name:  # TODO: Deduplicate code
  of "ssdeep":
    discard fuzzy_hash_buf(data, data_size.uint32, hashOut.cstring)
    if '\0' in hashOut: hashOut.setLen hashOut.find('\0')
  of "md5":
    var hCtx = init[RHASH_MD5]()
    var digest: Digest
    let mB = (data.pointer, data_size.int)
    hCtx.update(mB)
    hCtx.final(digest)
    hashOut = $digest
  of "sha1":
    var hCtx = init[RHASH_SHA1]()
    var digest: Digest
    let mB = (data.pointer, data_size.int)
    hCtx.update(mB)
    hCtx.final(digest)
    hashOut = $digest
  of "sha256":
    var hCtx = init[RHASH_SHA256]()
    var digest: Digest
    let mB = (data.pointer, data_size.int)
    hCtx.update(mB)
    hCtx.final(digest)
    hashOut = $digest
  else:
    return false  # Unsupported hash algorithm
  copyMem(output, hashOut.cstring, hashOut.len)
  output_size = hashOut.len.uint


proc get_hashes(output: ptr pe_hash_t, name: cstring, data: ptr uint8, data_size: uint): pe_err_e =
  ## Hash the given data with all the available hash functions. 
  ## Output will be copied to `output` parameter.
  for alg in ["md5", "sha1", "sha256", "ssdeep"]:
    var
      hash_value = newString(pe_hash_recommended_size())
      hash_maxsize = pe_hash_recommended_size()
      hvCstring = hash_value.cstring
    if not pe_hash_raw_data(hvCstring, hash_maxsize, alg.cstring, data, data_size): return LIBPE_E_HASHING_FAILED
    gHashStrings.add($hvCstring)
    case alg:
    of "md5":
      output[].md5 = gHashStrings[gHashStrings.len-1].cstring
    of "sha1":
      output.sha1 = addr gHashStrings[gHashStrings.len-1][0]
    of "sha256":
      output.sha256 = addr gHashStrings[gHashStrings.len-1][0]
    of "ssdeep":
      output.ssdeep = addr gHashStrings[gHashStrings.len-1][0]
    else:
      discard
    gHashStrings.add($name)
    output.name = addr gHashStrings[gHashStrings.len-1][0]

proc get_headers_dos_hash(ctx: ptr pe_ctx_t, output: ptr pe_hash_t): pe_err_e =
  ## Hash PE dos header with all the available hash functions.
  let data = pe_dos(ctx)
  let data_size = sizeof(IMAGE_DOS_HEADER).uint
  return get_hashes(output, "IMAGE_DOS_HEADER", cast [ptr uint8](data), data_size)

proc get_headers_coff_hash(ctx: ptr pe_ctx_t, output: ptr pe_hash_t): pe_err_e =
  ## Hash PE coff header with all the available hash functions.
  let data = pe_coff(ctx)
  let data_size = sizeof(IMAGE_COFF_HEADER).uint
  return get_hashes(output, "IMAGE_COFF_HEADER", cast [ptr uint8](data), data_size)

proc get_headers_optional_hash(ctx: ptr pe_ctx_t, output: ptr pe_hash_t): pe_err_e =
  ## Hash PE optional header with all the available hash functions.
  let sample = pe_optional(ctx) 
  let hType = sample[].`type`
  case hType:
  of MAGIC_PE32.uint16:
    let data = sample[].h_32
    let data_size = sizeof(IMAGE_OPTIONAL_HEADER_32).uint
    return get_hashes(output, "IMAGE_OPTIONAL_HEADER_32", cast [ptr uint8](data), data_size)
  of MAGIC_PE64.uint16:
    let data = sample[].h_64
    let data_size = sizeof(IMAGE_OPTIONAL_HEADER_64).uint
    return get_hashes(output, "IMAGE_OPTIONAL_HEADER_64", cast [ptr uint8](data), data_size)
  else:
    return  # Unknown header type

proc pe_get_headers_hashes*(ctx: ptr pe_ctx_t): ptr pe_hash_headers_t =
  ## Hash all the PE headers with all the available hash functions.
  if not ctx.cached_data.hash_headers.isNil: return ctx.cached_data.hash_headers
  var res: pe_hash_headers_t
  var hash: pe_hash_t
  gHashes.add(hash)
  res.dos = addr gHashes[gHashes.len - 1]
  gHashes.add(hash)
  res.coff = addr gHashes[gHashes.len - 1]
  gHashes.add(hash)
  res.optional = addr gHashes[gHashes.len - 1]
  var status = LIBPE_E_OK
  res.err = LIBPE_E_OK
  status = get_headers_dos_hash(ctx, res.dos)
  status = get_headers_coff_hash(ctx, res.coff)
  status = get_headers_optional_hash(ctx, res.optional)
  gHashHeaders.add(res)
  return addr gHashHeaders[gHashHeaders.len-1]

proc pe_get_sections_hash*(ctx: ptr pe_ctx_t): ptr pe_hash_sections_t =
  ## Hash all the PE sections with all the available hash functions.
  if not ctx.cached_data.hash_sections.isNil: return ctx.cached_data.hash_sections
  var res: pe_hash_sections_t
  var resSect: HashSections
  gHashSectArray.add(resSect)
  gHashSections.add(res)
  res.sections = addr gHashSectArray[gHashSectArray.len - 1]
  var sectCount = 0
  for sect in ctx[].sections:
    let data_size = sect.SizeOfRawData
    let data = ctx.map_addr + sect.PointerToRawData
    if data_size == 0: continue
    if not pe_can_read(ctx, data, data_size): continue  # unable to read sections data
    var name = sect[].getName().cstring
    var section_hash: pe_hash_t
    var status = get_hashes(addr section_hash, name, cast[ptr uint8](data), data_size)
    gHashes.add(section_hash)
    if status != LIBPE_E_OK:
      res.err = status
      break
    res.sections[sectCount] = addr gHashes[gHashes.len - 1]
    sectCount.inc
  gHashSections.add(res)
  return addr gHashSections[gHashSections.len - 1]

proc pe_get_file_hash*(ctx: ptr pe_ctx_t): ptr pe_hash_t =
  ## Hash the in-memory file with all the available hash functions.
  if not ctx.cached_data.hash_file.isNil: return ctx.cached_data.hash_file
  var hash: pe_hash_t
  let data_size = pe_filesize(ctx)
  if get_hashes(addr hash, "PEfile hash".cstring, cast[ptr uint8](ctx.map_addr), data_size.uint) == LIBPE_E_OK:
    gHashes.add(hash)
    return addr gHashes[gHashes.len - 1]

proc pe_imphash*(ctx: ptr pe_ctx_t, flavor: pe_imphash_flavor_e): cstring =
  ## Generate imports hash as PEFile or Mandiant flavor. Not implemented
  result = "Not implemented"

# PE Analysis
proc pe_fpu_trick*(ctx: ptr pe_ctx_t): bool =
  ## Not implemented - I doubt if this is relevant. To be implemented using yara.
  ## Left for compatibility
  return false

proc cpl_analysis*(ctx: ptr pe_ctx_t): cint =
  result = 0
  let
    hdr_coff_ptr = pe_coff(ctx)
    hdr_dos_ptr = pe_dos(ctx)
  if hdr_coff_ptr.isNil or hdr_dos_ptr.isNil: return 0

  let 
    characteristics1 = (
      IMAGE_FILE_EXECUTABLE_IMAGE or
      IMAGE_FILE_LINE_NUMS_STRIPPED or
      IMAGE_FILE_LOCAL_SYMS_STRIPPED or
      IMAGE_FILE_BYTES_REVERSED_LO or
      IMAGE_FILE_32BIT_MACHINE or
      IMAGE_FILE_DLL or
      IMAGE_FILE_BYTES_REVERSED_HI
    ).uint16
    characteristics2 = ( 
      IMAGE_FILE_EXECUTABLE_IMAGE or
      IMAGE_FILE_LINE_NUMS_STRIPPED or
      IMAGE_FILE_LOCAL_SYMS_STRIPPED or
      IMAGE_FILE_BYTES_REVERSED_LO or
      IMAGE_FILE_32BIT_MACHINE or 
      IMAGE_FILE_DEBUG_STRIPPED or
      IMAGE_FILE_DLL or
      IMAGE_FILE_BYTES_REVERSED_HI
    ).uint16
    characteristics3 = (
      IMAGE_FILE_EXECUTABLE_IMAGE or
      IMAGE_FILE_LINE_NUMS_STRIPPED or
      IMAGE_FILE_32BIT_MACHINE or
      IMAGE_FILE_DEBUG_STRIPPED or
      IMAGE_FILE_DLL
    ).uint16
  if  (
        hdr_coff_ptr.TimeDateStamp == 708992537 or 
        hdr_coff_ptr.TimeDateStamp > 1354555867
      ) and (
        hdr_coff_ptr.Characteristics == characteristics1 or
        hdr_coff_ptr.Characteristics == characteristics2 or
        hdr_coff_ptr.Characteristics == characteristics3
      ) and hdr_dos_ptr.e_sp == 0xb8: return 1

proc pe_get_cpl_analysis*(ctx: ptr pe_ctx_t): cint =
  return (if pe_is_dll(ctx): cpl_analysis(ctx) else: -1)

proc pe_check_fake_entrypoint*(ctx: ptr pe_ctx_t, ep: uint32): ptr IMAGE_SECTION_HEADER =
  let num_sections = pe_sections_count(ctx)
  if num_sections == 0: return

  result = pe_rva2section(ctx, ep)

  if bool(result.Characteristics and IMAGE_SCN_CNT_CODE.uint32): return cast[ptr IMAGE_SECTION_HEADER](0)

proc pe_has_fake_entrypoint*(ctx: ptr pe_ctx_t): cint =
  result = 0
  let optional = pe_optional(ctx)
  if optional.isNil: return -1

  let ep = ( if not optional.h_32.isNil: optional.h_32.AddressOfEntryPoint 
    else: (
        if not optional.h_64.isNil: optional.h_64.AddressOfEntryPoint else: 0.uint32
      )
  )
  if ep == 0: return -2
  if not pe_check_fake_entrypoint(ctx, ep).isNil: return 1  # fake

proc pe_get_tls_callback*(ctx: ptr pe_ctx_t): cint =
  ## Not implemented: misc.c:162
  result = LIBPE_E_NO_FUNCTIONS_FOUND.cint

# Resources

proc pe_resource_find_parent_node_by_type_and_level*(
  node: ptr pe_resource_node_t; `type`: pe_resource_node_type_e;
  dirLevel: uint32): ptr pe_resource_node_t =
  if node.isNil: return
  var parent = node.parentNode
  while not parent.isNil:
    if parent.`type` == `type` and parent.dirLevel == dirLevel: return parent
    parent = parent.parentNode

proc pe_resource_root_node*(node: ptr pe_resource_node_t): ptr pe_resource_node_t =
  ## TODO: make tests
  if node.isNil: return
  var parent = node.parentNode
  result = parent.parentNode
  while not parent.isNil:
    if parent.parentNode.isNil: return parent
    parent = parent.parentNode

proc pe_resource_find_node_by_type_and_level*(node: ptr pe_resource_node_t;
    `type`: pe_resource_node_type_e; dirLevel: uint32): ptr pe_resource_node_t =
  ## Unimplemented
  result = node

proc pe_resource_search_nodes*(res: ptr pe_resource_node_search_result_t;
                               node: ptr pe_resource_node_t;
                               predicate: pe_resource_node_predicate_fn) =
  ## Unimplemented
  if node.isNil: return

  if predicate(node):
    var item {.global.} : pe_resource_node_search_result_item_t
    if item.node == node:
      # res.items[].add(item)  # TODO: append item to some kind of container
      res.count.inc

  pe_resource_search_nodes(res, node.childNode, predicate)
  pe_resource_search_nodes(res, node.nextNode, predicate)

proc pe_resource_entry_info_lookup*(name_offset: uint32): ptr pe_resource_entry_info_t =
  for entInfo in g_resource_dataentry_info_table:
    if entInfo.`type`.uint == name_offset:
      var found {.global.} = entInfo  # instead returning unsafeAddr to const
      return addr found

proc pe_resource_last_child_node*(parent_node: ptr pe_resource_node_t): ptr pe_resource_node_t =
  if parent_node.isNil: return

  var child = parent_node.childNode
  while not child.isNil:
    if not child.isNil:
      return child
    child = child.nextNode

proc pe_resource_base_ptr(ctx: ptr pe_ctx_t): ptr IMAGE_RESOURCE_DIRECTORY = # or returns just `pointer`
  let directory = pe_directory_by_entry(ctx, IMAGE_DIRECTORY_ENTRY_RESOURCE)
  if directory.isNil: return  # "Resource directory does not exist"
  if directory.VirtualAddress == 0 or directory.Size == 0: return  # "Resource directory VA is zero"

  let offset = pe_rva2ofs(ctx, directory.VirtualAddress)
  result = cast[ptr IMAGE_RESOURCE_DIRECTORY](ctx.map_addr + offset)
  if not pe_can_read(ctx, result, sizeof(IMAGE_RESOURCE_DIRECTORY).uint): return  # Cannot read IMAGE_RESOURCE_DIRECTORY

proc pe_resource_create_node(depth: uint8, `type`: pe_resource_node_type_e, raw_ptr: pointer, parent_node: ptr pe_resource_node_t): ptr pe_resource_node_t =
  var node: pe_resource_node_t
  let nIdx = gResNodes.len
  gResNodes.add(node)
  gResNodes[nIdx].depth = depth
  gResNodes[nIdx].`type` = `type`

  if not parent_node.isNil:
    gResNodes[nIdx].dirLevel = (if parent_node.`type` == LIBPE_RDT_RESOURCE_DIRECTORY: parent_node.dirLevel + 1 else: parent_node.dirLevel)
  else: 
    gResNodes[nIdx].dirLevel = 0

  if not parent_node.isNil:
    gResNodes[nIdx].parentNode = parent_node
    if parent_node.childNode.isNil: parent_node.childNode = addr gResNodes[nIdx]
    else:
      var last_child_node {.global.} : pe_resource_node_t
      last_child_node = pe_resource_last_child_node(parent_node)[]
      if not (addr last_child_node).isNil: last_child_node.nextNode = addr gResNodes[nIdx]

  gResNodes[nIdx].raw.raw_ptr = raw_ptr

  case `type`:
  of LIBPE_RDT_RESOURCE_DIRECTORY: gResNodes[nIdx].raw.resourceDirectory = cast[ptr IMAGE_RESOURCE_DIRECTORY](raw_ptr)
  of LIBPE_RDT_DIRECTORY_ENTRY: gResNodes[nIdx].raw.directoryEntry = cast[ptr IMAGE_RESOURCE_DIRECTORY_ENTRY](raw_ptr)
  of LIBPE_RDT_DATA_STRING: gResNodes[nIdx].raw.dataString = cast[ptr IMAGE_RESOURCE_DATA_STRING_U](raw_ptr)
  of LIBPE_RDT_DATA_ENTRY: gResNodes[nIdx].raw.dataEntry = cast[ptr IMAGE_RESOURCE_DATA_ENTRY](raw_ptr)
  else: discard  # Invalid Node Type

  result = addr gResNodes[nIdx]

proc pe_resource_parse_string_u*(ctx: ptr pe_ctx_t, output: typeof(nil), output_size: uint, data_string_ptr: ptr IMAGE_RESOURCE_DATA_STRING_U): cstring =
  if data_string_ptr.isNil: return
  if not pe_can_read(ctx, addr data_string_ptr.String, data_string_ptr.Length): return  # Cannot read string from IMAGE_RESOURCE_DATA_STRING_U
  var nStr = $cast[WideCString](data_string_ptr)
  nStr.setLen(data_string_ptr.Length + 1)
  result = cstring(nStr)

proc pe_resource_parse_string_u*(ctx: ptr pe_ctx_t, output: var cstring, output_size: uint, data_string_ptr: ptr IMAGE_RESOURCE_DATA_STRING_U): cstring =
  if data_string_ptr.isNil: return
  if not pe_can_read(ctx, addr data_string_ptr.String, data_string_ptr.Length): return  # Cannot read string from IMAGE_RESOURCE_DATA_STRING_U
  let buffer_size = (if output_size == 0: data_string_ptr.Length + 1 else: output_size.uint16)
  var nStr = $cast[WideCString](data_string_ptr)
  nStr.setLen(buffer_size)
  output = cstring(nStr)
  return output

proc pe_resource_parse_nodes(ctx: ptr pe_ctx_t, node: ptr pe_resource_node_t): bool =
  result = true
  let nIdx = gResNodes.len-1
  case node.`type`:
  of LIBPE_RDT_RESOURCE_DIRECTORY:
    let resdir_ptr = node.raw.resourceDirectory
    let total_entries = resdir_ptr.NumberOfIdEntries + resdir_ptr.NumberOfNamedEntries
    var first_entry_ptr = resdir_ptr + sizeof(IMAGE_RESOURCE_DIRECTORY).uint
    for i in 0..<total_entries.int:
      let entry = cast[ptr IMAGE_RESOURCE_DIRECTORY_ENTRY](first_entry_ptr + i.uint * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY).uint)
      if not pe_can_read(ctx, entry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY).uint):
        discard "Cannot read IMAGE_RESOURCE_DIRECTORY_ENTRY"
      gResNodes[nIdx] = pe_resource_create_node((node.depth + 1).uint8, LIBPE_RDT_DIRECTORY_ENTRY, entry, node)[]
      discard pe_resource_parse_nodes(ctx, addr gResNodes[nIdx])
  of LIBPE_RDT_DIRECTORY_ENTRY:
    let entry_ptr = node.raw.directoryEntry
    if entry_ptr.isNil: return false
    if entry_ptr.u0.data.NameIsString != 0.uint:
      var data_string_ptr = ctx.cached_data.resources.resource_base_ptr + entry_ptr.u0.data.NameOffset
      if not pe_can_read(ctx, data_string_ptr, sizeof(IMAGE_RESOURCE_DATA_STRING_U).uint): return  # Cannot read IMAGE_RESOURCE_DATA_STRING_U
      node.name = pe_resource_parse_string_u(ctx, nil, 0, cast[ptr IMAGE_RESOURCE_DATA_STRING_U](data_string_ptr))
      gResNodes[nIdx] = pe_resource_create_node((node.depth + 1).uint8, LIBPE_RDT_DATA_STRING, data_string_ptr, node)[]
      discard pe_resource_parse_nodes(ctx, addr gResNodes[nIdx])
    if entry_ptr.u1.data.DataIsDirectory != 0.uint:
      var child_resdir_ptr = cast[ptr IMAGE_RESOURCE_DIRECTORY](ctx.cached_data.resources.resource_base_ptr + entry_ptr.u1.data.OffsetToDirectory)
      if not pe_can_read(ctx, child_resdir_ptr, sizeof(IMAGE_RESOURCE_DIRECTORY).uint): discard "Cannot read IMAGE_RESOURCE_DIRECTORY"
      gResNodes[nIdx] = pe_resource_create_node((node.depth + 1).uint8, LIBPE_RDT_RESOURCE_DIRECTORY, child_resdir_ptr, node)[]
    else:
      var data_resdir_ptr = cast[ptr IMAGE_RESOURCE_DIRECTORY](ctx.cached_data.resources.resource_base_ptr + entry_ptr.u1.data.OffsetToDirectory)
      if not pe_can_read(ctx, data_resdir_ptr, sizeof(IMAGE_RESOURCE_DATA_ENTRY).uint): discard "Cannot read IMAGE_RESOURCE_DIRECTORY"
      gResNodes[nIdx] = pe_resource_create_node((node.depth + 1).uint8, LIBPE_RDT_DATA_ENTRY, data_resdir_ptr, node)[]
    discard pe_resource_parse_nodes(ctx, addr gResNodes[nIdx])
  of LIBPE_RDT_DATA_STRING:
    let data_string_ptr = node.raw.dataString
    if not pe_can_read(ctx, data_string_ptr, sizeof(IMAGE_RESOURCE_DATA_STRING_U).uint): discard "Cannot read IMAGE_RESOURCE_DATA_STRING_U"
    # var buffer = pe_resource_parse_string_u(ctx, nil, 0, data_string_ptr)  # only for debugging purposes
  of LIBPE_RDT_DATA_ENTRY:
    discard "Not Implemented"
  else:
    return false  # Invalid node type


proc pe_resource_parse(ctx: ptr pe_ctx_t, resource_base_ptr: ptr IMAGE_RESOURCE_DIRECTORY): ptr pe_resource_node_t =
  discard pe_resource_create_node(0.uint8, LIBPE_RDT_RESOURCE_DIRECTORY, resource_base_ptr, cast [ptr pe_resource_node_t](nil))[]
  discard pe_resource_parse_nodes(ctx, addr gResNodes[0])
  return addr gResNodes[0]

proc pe_resources*(ctx: ptr pe_ctx_t): ptr pe_resources_t =
  if not ctx.cached_data.resources.isNil: return ctx.cached_data.resources

  var res_ptr {.global.} : pe_resources_t

  ctx.cached_data.resources = addr res_ptr
  ctx.cached_data.resources.err = LIBPE_E_OK

  ctx.cached_data.resources.resource_base_ptr = pe_resource_base_ptr(ctx)
  if not ctx.cached_data.resources.resource_base_ptr.isNil:
    ctx.cached_data.resources.root_node = pe_resource_parse(ctx, cast[ptr IMAGE_RESOURCE_DIRECTORY](ctx.cached_data.resources.resource_base_ptr))  # why is this cast needed here?

  result = ctx.cached_data.resources
  
