import libpe/def_enums
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

when defined(MacOsX):
  const libpePath = "/usr/local/opt/pev/lib/libpe.1.0.dylib"
elif defined(mingw):
  const libpePath = "libpe.dll"
elif defined(Windows):
  const libpePath = "libpe.dll"
  ## TODO: Linux

{.push dynlib: libpePath.}

{.pragma: imppeHdr, header: "pe.h".}
{.pragma: impError, header: "error.h".}
{.pragma: impresourcesHdr, header: "resources.h".}

defineEnum(pe_option_e)
const
  MAGIC_MZ* = 0x00005A4D
  MAX_DIRECTORIES* = 16
  MAX_SECTIONS* = 96
  MAX_DLL_NAME* = 256
  MAX_FUNCTION_NAME* = 512
  IMAGE_ORDINAL_FLAG32* = 0x80000000
  IMAGE_ORDINAL_FLAG64* = 0x8000000000000000'u64
  SIGNATURE_NE* = 0x0000454E
  SIGNATURE_PE* = 0x00004550
  LIBPE_OPT_NOCLOSE_FD* = 1.pe_option_e  # Keeps stream open for further usage.
  LIBPE_OPT_OPEN_RW* = 2.pe_option_e  # Open file for read and writing

type
  pe_options_e* {.importc, imppeHdr.} = uint16  ##   bitmasked pe_option_e values

  pe_file_t* {.bycopy, importc, imppeHdr.} = object
    dos_hdr*: ptr IMAGE_DOS_HEADER  ##   DOS header
    signature*: uint32  ##   Signature
    coff_hdr*: ptr IMAGE_COFF_HEADER  ##   COFF header
    optional_hdr_ptr*: pointer  ##   Optional header
    optional_hdr*: IMAGE_OPTIONAL_HEADER  ##   Directories
    num_directories*: uint32  ##   Directories
    directories_ptr*: pointer
    directories*: ptr ptr IMAGE_DATA_DIRECTORY  ##   array up to MAX_DIRECTORIES  ##      Sections
    num_sections*: uint16  ##   array up to MAX_DIRECTORIES  ##      Sections
    sections_ptr*: pointer
    sections*: ptr ptr IMAGE_SECTION_HEADER  ##   array up to MAX_SECTIONS
    entrypoint*: uint64  ##   array up to MAX_SECTIONS
    imagebase*: uint64

  pe_cached_data_t* {.bycopy, importc, imppeHdr.} = object
    imports*: ptr pe_imports_t  ##   Parsed directories
    exports*: ptr pe_exports_t  ##   Hashes
    hash_headers*: ptr pe_hash_headers_t  ##   Hashes
    hash_sections*: ptr pe_hash_sections_t
    hash_file*: ptr pe_hash_t  ##   Resources
    resources*: ptr pe_resources_t  ##   Resources
  
  pe_ctx* {.bycopy, imppeHdr, importc: "struct pe_ctx".} = object
    stream*: File
    path*: cstring
    map_addr*: pointer
    map_size*: clong
    map_end*: ptr uint
    pe*: pe_file_t
    cached_data*: pe_cached_data_t

  pe_ctx_t* {.importc, imppeHdr.} = pe_ctx

proc pe_can_read*(ctx: ptr pe_ctx_t, `ptr`: pointer, size: uint): bool {.
    importc, cdecl, imppeHdr.}
proc pe_load_file*(ctx: ptr pe_ctx_t, path: cstring): pe_err_e {.importc, cdecl,
    imppeHdr.}
proc pe_load_file_ext*(ctx: ptr pe_ctx_t, path: cstring, options: pe_options_e): pe_err_e {.
    importc, cdecl, imppeHdr.}
proc pe_unload*(ctx: ptr pe_ctx_t): pe_err_e {.importc, cdecl, imppeHdr.}
proc pe_parse*(ctx: ptr pe_ctx_t): pe_err_e {.importc, cdecl, imppeHdr.}
proc pe_is_loaded*(ctx: ptr pe_ctx_t): bool {.importc, cdecl, imppeHdr.}
proc pe_is_pe*(ctx: ptr pe_ctx_t): bool {.importc, cdecl, imppeHdr.}
proc pe_is_dll*(ctx: ptr pe_ctx_t): bool {.importc, cdecl, imppeHdr.}
proc pe_filesize*(ctx: ptr pe_ctx_t): uint64 {.importc, cdecl, imppeHdr.}
proc pe_rva2section*(ctx: ptr pe_ctx_t, rva: uint64): ptr IMAGE_SECTION_HEADER {.
    importc, cdecl, imppeHdr.}
proc pe_rva2ofs*(ctx: ptr pe_ctx_t, rva: uint64): uint64 {.importc, cdecl,
    imppeHdr.}
proc pe_ofs2rva*(ctx: ptr pe_ctx_t, ofs: uint64): uint64 {.importc, cdecl,
    imppeHdr.}
proc pe_dos*(ctx: ptr pe_ctx_t): ptr IMAGE_DOS_HEADER {.importc, cdecl, imppeHdr.}  ##   Header functions

proc pe_coff*(ctx: ptr pe_ctx_t): ptr IMAGE_COFF_HEADER {.importc, cdecl,
    imppeHdr.}
proc pe_optional*(ctx: ptr pe_ctx_t): ptr IMAGE_OPTIONAL_HEADER {.importc,
    cdecl, imppeHdr.}
proc pe_directories_count*(ctx: ptr pe_ctx_t): uint32 {.importc, cdecl, imppeHdr.}
proc pe_directories*(ctx: ptr pe_ctx_t): ptr UncheckedArray[ptr IMAGE_DATA_DIRECTORY] {.importc,
    cdecl, imppeHdr.}
proc pe_directory_by_entry*(ctx: ptr pe_ctx_t, entry: ImageDirectoryEntry): ptr IMAGE_DATA_DIRECTORY {.
    importc, cdecl, imppeHdr.}
proc pe_sections_count*(ctx: ptr pe_ctx_t): uint16 {.importc, cdecl, imppeHdr.}
proc pe_sections*(ctx: ptr pe_ctx_t): ptr UncheckedArray[ptr IMAGE_SECTION_HEADER] {.importc,
    cdecl, imppeHdr.}
proc pe_section_by_name*(ctx: ptr pe_ctx_t, section_name: cstring): ptr IMAGE_SECTION_HEADER {.
    importc, cdecl, imppeHdr.}
proc pe_section_name*(ctx: ptr pe_ctx_t, section_hdr: ptr IMAGE_SECTION_HEADER,
                      out_name: cstring, out_name_size: uint): cstring {.
    importc, cdecl, imppeHdr.}
proc pe_machine_type_name*(`type`: MachineType): cstring {.importc, cdecl,
    imppeHdr.}
proc pe_image_characteristic_name*(characteristic: ImageCharacteristics): cstring {.
    importc, cdecl, imppeHdr.}
proc pe_image_dllcharacteristic_name*(characteristic: ImageDllCharacteristics): cstring {.
    importc, cdecl, imppeHdr.}
proc pe_windows_subsystem_name*(subsystem: WindowsSubsystem): cstring {.importc,
    cdecl, imppeHdr.}
proc pe_directory_name*(entry: ImageDirectoryEntry): cstring {.importc, cdecl,
    imppeHdr.}
proc pe_section_characteristic_name*(characteristic: SectionCharacteristics): cstring {.
    importc, cdecl, imppeHdr.}
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
proc pe_imports*(ctx: ptr pe_ctx_t): ptr pe_imports_t {.importc, cdecl, imppeHdr.}
proc pe_exports*(ctx: ptr pe_ctx_t): ptr pe_exports_t {.importc, cdecl, imppeHdr.}
proc pe_resources*(ctx: ptr pe_ctx_t): ptr pe_resources_t {.importc, cdecl,
    imppeHdr.}
proc pe_calculate_entropy_file*(ctx: ptr pe_ctx_t): cdouble {.importc, cdecl,
    imppeHdr.}
proc pe_fpu_trick*(ctx: ptr pe_ctx_t): bool {.importc, cdecl, imppeHdr.}
proc pe_get_cpl_analysis*(ctx: ptr pe_ctx_t): cint {.importc, cdecl, imppeHdr.}
proc pe_has_fake_entrypoint*(ctx: ptr pe_ctx_t): cint {.importc, cdecl, imppeHdr.}
proc pe_get_tls_callback*(ctx: ptr pe_ctx_t): cint {.importc, cdecl, imppeHdr.}
proc pe_error_msg*(error: pe_err_e): cstring {.importc, cdecl, impError.}
proc pe_error_print*(stream: File; error: pe_err_e) {.importc, impError.}

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

iterator sections*(ctx: var pe_ctx_t): ptr IMAGE_SECTION_HEADER =
  let peSections = pe_sections(addr ctx)
  for i in 0..<pe_sections_count(addr ctx).Natural: 
    yield peSections[i]

iterator directories*(ctx: var pe_ctx_t): (ImageDirectoryEntry, ptr IMAGE_DATA_DIRECTORY) =
  let peDirectories = pe_directories(addr ctx)
  for i in 0..<pe_directories_count(addr ctx).Natural:
    if peDirectories[i].Size == 0: continue
    yield (i.ImageDirectoryEntry, peDirectories[i])
