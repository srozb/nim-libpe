import error
import strutils

{.pragma: impexportsHdr, header: "exports.h".}
{.experimental: "codeReordering".}

type
  pe_exported_function_t* {.bycopy, importc, impexportsHdr.} = object
    ordinal*: uint32  ##   ordinal of the function
    name*: cstring  ##   name of the function
    fwd_name*: cstring  ##   name of the forwarded function
    address*: uint32  ##   address of the function

  pe_exports_t* {.bycopy, importc, impexportsHdr.} = object
    err*: pe_err_e
    name*: cstring  ##   name of the DLL
    functions_count*: uint32  ##   name of the DLL
    functions*: ptr UncheckedArray[pe_exported_function_t]   ##   array of exported functions

# proc pe_exports_dealloc*(exports: ptr pe_exports_t) {.importc, cdecl,
#     impexportsHdr.}

iterator items*(x: ptr pe_exports_t): pe_exported_function_t =
  for i in 0..<x.functions_count: 
    if x.functions[i].name.len > 0: yield x.functions[i]

proc `[]`*(x: ptr pe_exports_t, k: string): pe_exported_function_t = 
  for exp in x.items:
    if ($exp.name).toLower == k.toLower: return exp