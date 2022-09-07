import error
import def_enums

defineEnum(pe_imphash_flavor_e)

const
  LIBPE_IMPHASH_FLAVOR_MANDIANT* = (1).pe_imphash_flavor_e
  LIBPE_IMPHASH_FLAVOR_PEFILE* = (2).pe_imphash_flavor_e
  
type
  HashSections* = array[0..96, ptr pe_hash_t]  # TODO: MAX_SECTIONS

  pe_hash_t* {.bycopy.} = object
    name*: cstring
    md5*: cstring
    ssdeep*: cstring
    sha1*: cstring
    sha256*: cstring

  pe_hash_headers_t* {.bycopy.} = object
    err*: pe_err_e
    dos*: ptr pe_hash_t
    coff*: ptr pe_hash_t
    optional*: ptr pe_hash_t

  pe_hash_sections_t* {.bycopy.} = object
    err*: pe_err_e
    count*: uint32
    sections*: ptr HashSections  # BUG: Can't read all sections

# proc pe_hash_headers_dealloc*(obj: ptr pe_hash_headers_t) {.importc, cdecl,
#     imphashesHdr.}
# proc pe_hash_sections_dealloc*(obj: ptr pe_hash_sections_t) {.importc, cdecl,
#     imphashesHdr.}
# proc pe_hash_dealloc*(obj: ptr pe_hash_t) {.importc, cdecl, imphashesHdr.}

