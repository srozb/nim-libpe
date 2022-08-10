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


{.pragma: imperrorHdr,
  header: "libpe/libpe/include/libpe/error.h".}
{.experimental: "codeReordering".}
defineEnum(pe_err_e) 

const
  LIBPE_E_OK* = (0).pe_err_e
  LIBPE_E_ALLOCATION_FAILURE* = (-23).pe_err_e 
  LIBPE_E_OPEN_FAILED* = (LIBPE_E_ALLOCATION_FAILURE + 1).pe_err_e
  LIBPE_E_FDOPEN_FAILED* = (LIBPE_E_OPEN_FAILED + 1).pe_err_e
  LIBPE_E_FSTAT_FAILED* = (LIBPE_E_FDOPEN_FAILED + 1).pe_err_e
  LIBPE_E_NOT_A_FILE* = (LIBPE_E_FSTAT_FAILED + 1).pe_err_e
  LIBPE_E_NOT_A_PE_FILE* = (LIBPE_E_NOT_A_FILE + 1).pe_err_e
  LIBPE_E_INVALID_LFANEW* = (LIBPE_E_NOT_A_PE_FILE + 1).pe_err_e
  LIBPE_E_MISSING_COFF_HEADER* = (LIBPE_E_INVALID_LFANEW + 1).pe_err_e
  LIBPE_E_MISSING_OPTIONAL_HEADER* = (LIBPE_E_MISSING_COFF_HEADER + 1).pe_err_e
  LIBPE_E_INVALID_SIGNATURE* = (LIBPE_E_MISSING_OPTIONAL_HEADER + 1).pe_err_e
  LIBPE_E_UNSUPPORTED_IMAGE* = (LIBPE_E_INVALID_SIGNATURE + 1).pe_err_e
  LIBPE_E_MMAP_FAILED* = (LIBPE_E_UNSUPPORTED_IMAGE + 1).pe_err_e
  LIBPE_E_MUNMAP_FAILED* = (LIBPE_E_MMAP_FAILED + 1).pe_err_e
  LIBPE_E_CLOSE_FAILED* = (LIBPE_E_MUNMAP_FAILED + 1).pe_err_e
  LIBPE_E_TOO_MANY_DIRECTORIES* = (LIBPE_E_CLOSE_FAILED + 1).pe_err_e
  LIBPE_E_TOO_MANY_SECTIONS* = (LIBPE_E_TOO_MANY_DIRECTORIES + 1).pe_err_e
  LIBPE_E_INVALID_THUNK* = (LIBPE_E_TOO_MANY_SECTIONS + 1).pe_err_e 
  LIBPE_E_EXPORTS_CANT_READ_RVA* = (LIBPE_E_INVALID_THUNK + 1).pe_err_e 
  LIBPE_E_EXPORTS_CANT_READ_DIR* = (LIBPE_E_EXPORTS_CANT_READ_RVA + 1).pe_err_e
  LIBPE_E_EXPORTS_FUNC_NEQ_NAMES* = (LIBPE_E_EXPORTS_CANT_READ_DIR + 1).pe_err_e 
  LIBPE_E_HASHING_FAILED* = (LIBPE_E_EXPORTS_FUNC_NEQ_NAMES + 1).pe_err_e 
  LIBPE_E_NO_CALLBACKS_FOUND* = (LIBPE_E_HASHING_FAILED + 1).pe_err_e 
  LIBPE_E_NO_FUNCTIONS_FOUND* = (LIBPE_E_NO_CALLBACKS_FOUND + 1).pe_err_e 

proc pe_error_msg*(error: pe_err_e): cstring {.importc, cdecl, imperrorHdr.}
proc pe_error_print*(stream: File; error: pe_err_e) {.importc, cdecl,
    imperrorHdr.}
{.pop.}
