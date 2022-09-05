import def_enums
import hdr_dos
import hdr_coff
import hdr_optional
import imports
import exports
import hashes
import resources
import directories
import sections

defineEnum(pe_option_e)

const
  MAX_DIRECTORIES* = 16
  MAX_SECTIONS* = 96
  MAGIC_MZ* = 0x00005A4D
  MAX_DLL_NAME* = 256
  MAX_FUNCTION_NAME* = 512
  IMAGE_ORDINAL_FLAG32* = 0x80000000'u32
  IMAGE_ORDINAL_FLAG64* = 0x8000000000000000'u64
  SIGNATURE_NE* = 0x0000454E
  SIGNATURE_PE* = 0x00004550
  LIBPE_OPT_NOCLOSE_FD* = 1.pe_option_e  # Keeps stream open for further usage.
  LIBPE_OPT_OPEN_RW* = 2.pe_option_e  # Open file for read and writing

type
  Sections* = array[0..MAX_SECTIONS, ptr IMAGE_SECTION_HEADER]
  Directories* = array[0..MAX_DIRECTORIES, ptr IMAGE_DATA_DIRECTORY]

  pe_options_e* = uint16  ##   bitmasked pe_option_e values

  pe_file_t* {.bycopy, header: "pe.h".} = object
    dos_hdr*: ptr IMAGE_DOS_HEADER  ##   DOS header
    signature*: uint32  ##   Signature
    coff_hdr*: ptr IMAGE_COFF_HEADER  ##   COFF header
    optional_hdr_ptr*: pointer  ##   Optional header
    optional_hdr*: IMAGE_OPTIONAL_HEADER  ##   Directories
    num_directories*: uint32  ##   Directories
    directories_ptr*: pointer
    directories*: ptr Directories  ##   array up to MAX_DIRECTORIES  ##      Sections
    num_sections*: uint16  ##   array up to MAX_DIRECTORIES  ##      Sections
    sections_ptr*: pointer
    sections*: ptr Sections  ##   array up to MAX_SECTIONS
    entrypoint*: uint64  ##   array up to MAX_SECTIONS
    imagebase*: uint64

  pe_cached_data_t* {.bycopy.} = object
    imports*: ptr pe_imports_t  ##   Parsed directories
    exports*: ptr pe_exports_t  ##   Hashes
    hash_headers*: ptr pe_hash_headers_t  ##   Hashes
    hash_sections*: ptr pe_hash_sections_t
    hash_file*: ptr pe_hash_t  ##   Resources
    resources*: ptr pe_resources_t  ##   Resources
  
  pe_ctx* {.bycopy.} = object
    stream*: File
    path*: cstring
    map_addr*: pointer
    map_size*: clong
    map_end*: ptr uint
    pe*: pe_file_t
    cached_data*: pe_cached_data_t

  pe_ctx_t* = pe_ctx
