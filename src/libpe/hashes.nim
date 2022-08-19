import error
import def_enums

{.pragma: imphashesHdr, header: "hashes.h".}

defineEnum(pe_imphash_flavor_e)

const
  LIBPE_IMPHASH_FLAVOR_MANDIANT* = (1).pe_imphash_flavor_e
  LIBPE_IMPHASH_FLAVOR_PEFILE* = (2).pe_imphash_flavor_e
  
type
  pe_hash_t* {.bycopy, importc, imphashesHdr.} = object
    name*: cstring
    md5*: cstring
    ssdeep*: cstring
    sha1*: cstring
    sha256*: cstring

  pe_hash_headers_t* {.bycopy, importc, imphashesHdr.} = object
    err*: pe_err_e
    dos*: ptr pe_hash_t
    coff*: ptr pe_hash_t
    optional*: ptr pe_hash_t

  pe_hash_sections_t* {.bycopy, importc, imphashesHdr.} = object
    err*: pe_err_e
    count*: uint32
    sections*: ptr ptr UncheckedArray[pe_hash_t]  # BUG: Can't read all sections

# proc pe_hash_headers_dealloc*(obj: ptr pe_hash_headers_t) {.importc, cdecl,
#     imphashesHdr.}
# proc pe_hash_sections_dealloc*(obj: ptr pe_hash_sections_t) {.importc, cdecl,
#     imphashesHdr.}
# proc pe_hash_dealloc*(obj: ptr pe_hash_t) {.importc, cdecl, imphashesHdr.}
