import std/memFiles
import pe
import exports
import imports
import resources
import hashes

var 
  mFile*: MemFile
  peDirs*: Directories
  peSects*: Sections
  gExports*: pe_exports_t
  gExportedFuncs*: seq[pe_exported_function_t]
  gImports*: pe_imports_t
  gImportedDlls*: seq[pe_imported_dll_t]
  gImportedFunctions*: seq[seq[pe_imported_function_t]]
  gImportedFunctionsName*: seq[string]
  gCachedData*: pe_cached_data_t
  gResNodes*: seq[pe_resource_node_t]
  gHashStrings*: seq[string]
  gHashHeaders*: seq[pe_hash_headers_t]
  gHashSections*: seq[pe_hash_sections_t]
  gHashSectArray*: seq[HashSections]
  gHashes*: seq[pe_hash_t]

proc deallocateAll*() = 
  gExports = pe_exports_t()
  gExportedFuncs = @[]
  gImports = pe_imports_t()
  gImportedDlls = @[]
  gImportedFunctions = @[]
  gImportedFunctionsName = @[]
  gCachedData = pe_cached_data_t()
  gResNodes = @[]
  gHashStrings = @[]
  gHashHeaders = @[]
  gHashSections = @[]
  gHashSectArray = @[]
  gHashes = @[]
