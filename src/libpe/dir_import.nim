type
  Union_dir_importh1* {.union, bycopy,
                        importc: "union Union_dir_importh1".} = object
    Characteristics*: uint32 ##   0 for terminating null import descriptor
    OriginalFirstThunk*: uint32 ##   RVA to original unbound IAT
                                
  IMAGE_IMPORT_DESCRIPTOR* {.bycopy, importc, header: "dir_import.h".} = object
    u1*: Union_dir_importh1
    TimeDateStamp*: uint32
    ForwarderChain*: uint32  ##   -1 if no forwarders
    Name*: uint32           
    FirstThunk*: uint32 ##   RVA to IAT (if bound this IAT has actual addresses)
                        
  IMAGE_IMPORT_BY_NAME* {.bycopy, importc, header: "dir_import.h".} = object ##   import name entry
    Hint*: uint16
    Name*: cstring
  Union_dir_importh2* {.union, bycopy,
                        importc: "union Union_dir_importh2".} = object
    ForwarderString*: uint64 ##   RVA to a forwarder string
    Function*: uint64        ##   Memory address of the imported function
    Ordinal*: uint64         ##   Ordinal value of imported API 
    AddressOfData*: uint64   ##   RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
                           
  IMAGE_THUNK_DATA64* {.bycopy, importc, header: "dir_import.h".} = object
    u1*: Union_dir_importh2
  Union_dir_importh3* {.union, bycopy,
                        importc: "union Union_dir_importh3".} = object
    ForwarderString*: uint32 ##   RVA to a forwarder string
    Function*: uint32        ##   Memory address of the imported function
    Ordinal*: uint32         ##   Ordinal value of imported API
    AddressOfData*: uint32   ##   RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
  IMAGE_THUNK_DATA32* {.bycopy, importc.} = object
    u1*: Union_dir_importh3
