import strutils

import error

{.push hint[ConvFromXtoItselfNotNeeded]: off.}
{.pragma: impimportsHdr, header: "imports.h".}
{.experimental: "codeReordering".}

type
  pe_imported_function_t* {.bycopy, importc, impimportsHdr.} = object
    name*: cstring
    hint*: uint16
    ordinal*: uint16

  pe_imported_dll_t* {.bycopy, importc, impimportsHdr.} = object
    err*: pe_err_e
    name*: cstring
    functions_count*: uint32
    functions*: ptr UncheckedArray[pe_imported_function_t]   ##   array of imported functions

  pe_imports_t* {.bycopy, importc, impimportsHdr.} = object
    err*: pe_err_e
    dll_count*: uint32
    dlls*: ptr UncheckedArray[pe_imported_dll_t]   ##   array of DLLs
  
proc pe_imports_dealloc*(imports: ptr pe_imports_t) {.importc, cdecl,
    impimportsHdr.}
{.pop.}

iterator items*(x: ptr pe_imports_t): pe_imported_dll_t =
  for i in 0..<x.dll_count: yield x.dlls[i]  # TODO: filter empty names

iterator items*(x: pe_imported_dll_t): pe_imported_function_t =
  for i in 0..<x.functions_count: yield x.functions[i]

proc `[]`*(x: ptr pe_imports_t, k: string): pe_imported_dll_t = 
  for imp in x.items:
    if ($imp.name).toLower == k.toLower: return imp

proc `[]`*(x: pe_imported_dll_t, k: string): pe_imported_function_t = 
  for imp in x.items:
    if ($imp.name).toLower == k.toLower: return imp
