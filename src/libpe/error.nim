import def_enums

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

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

{.pop.}

proc pe_error_msg*(error: pe_err_e): cstring =
  const errors = @[
    "no error",                 ## LIBPE_E_OK,
    "no functions found",       ##LIBPE_E_NO_FUNCIONS_FOUND
    "no callbacks found",       ##LIBPE_E_NO_CALLBACKS_FOUND
     "error calculating hash",  ## LIBPE_E_HASHING_FAILED
    "number of functions not equal to number of names", ##LIBPE_E_EXPORTS_FUNC_NEQ_NAMES
    "cannot read exports directory", ## LIBPE_E_EXPORTS_CANT_READ_DIR
    "cannot read relative virtual address", ##LIBPE_E_EXPORTS_CANT_READ_RVA
    "type punning failed",      ## LIBPE_E_TYPE_PUNNING_FAILED
    "too many sections",        ## LIBPE_E_TOO_MANY_SECTIONS,
    "too many directories",     ## LIBPE_E_TOO_MANY_DIRECTORIES,
    "close() failed",           ## LIBPE_E_CLOSE_FAILED,
    "munmap() failed",          ## LIBPE_E_MUNMAP_FAILED,
    "mmap() failed",            ## LIBPE_E_MMAP_FAILED,
    "unsupported image format", ## LIBPE_E_UNSUPPORTED_IMAGE,
    "invalid signature",        ## LIBPE_E_INVALID_SIGNATURE,
    "missing OPTIONAL header",  ## LIBPE_E_MISSING_OPTIONAL_HEADER,
    "missing COFF header",      ## LIBPE_E_MISSING_COFF_HEADER,
    "invalid e_lfanew",         ## LIBPE_E_INVALID_LFANEW,
    "not a PE file",            ## LIBPE_E_NOT_A_PE_FILE,
    "not a regular file",       ## LIBPE_E_NOT_A_FILE,
    "fstat() failed",           ## LIBPE_E_FSTAT_FAILED,
    "fdopen() failed",          ## LIBPE_E_FDOPEN_FAILED,
    "open() failed",            ## LIBPE_E_OPEN_FAILED,
    "allocation failure"]       ## LIBPE_E_ALLOCATION_FAILURE,

  return errors[error.int.abs].cstring

proc pe_error_print*(stream: File, error: pe_err_e) =
  stream.write(error.pe_error_msg)
