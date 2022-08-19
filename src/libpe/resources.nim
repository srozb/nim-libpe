import dir_resources
import error
import def_enums

{.pragma: impresourcesHdr, header: "resources.h".}

defineEnum(pe_resource_level_e)
defineEnum(pe_resource_node_type_e)

const
  LIBPE_RDT_LEVEL1* = (1).pe_resource_level_e
  LIBPE_RDT_LEVEL2* = (2).pe_resource_level_e
  LIBPE_RDT_LEVEL3* = (3).pe_resource_level_e
  LIBPE_RDT_RESOURCE_DIRECTORY* = (1).pe_resource_node_type_e
  LIBPE_RDT_DIRECTORY_ENTRY* = (2).pe_resource_node_type_e
  LIBPE_RDT_DATA_STRING* = (3).pe_resource_node_type_e
  LIBPE_RDT_DATA_ENTRY* = (4).pe_resource_node_type_e

type
  pe_ctx* {.incompleteStruct, impresourcesHdr, importc: "struct pe_ctx".} = object
  
  pe_ctx_t* {.importc, impresourcesHdr.} = pe_ctx
  Union_resourcesh1* {.union, bycopy, impresourcesHdr,
                       importc: "union Union_resourcesh1".} = object
    raw_ptr*: pointer  ##   We are allowed to rely on type-punning in C99, but not in C++.
    resourceDirectory*: ptr IMAGE_RESOURCE_DIRECTORY  ##   type == LIBPE_RDT_RESOURCE_DIRECTORY
    directoryEntry*: ptr IMAGE_RESOURCE_DIRECTORY_ENTRY  ##   type == LIBPE_RDT_DIRECTORY_ENTRY
    dataString*: ptr IMAGE_RESOURCE_DATA_STRING_U  ##   type == LIBPE_RDT_DATA_STRING
    dataEntry*: ptr IMAGE_RESOURCE_DATA_ENTRY  ##   type == LIBPE_RDT_DATA_ENTRY
  
  pe_resource_node* {.bycopy, impresourcesHdr,
                      importc: "struct pe_resource_node".} = object
    depth*: uint16
    dirLevel*: uint32  ##   pe_resouces_level_e
    `type`*: pe_resource_node_type_e  ##   pe_resouces_level_e
    name*: cstring
    raw*: Union_resourcesh1
    parentNode*: ptr pe_resource_node  ##   Points to the parent node, if any.
    childNode*: ptr pe_resource_node  ##   Points to the 1st child node, if any.
    nextNode*: ptr pe_resource_node  ##   Points to the next sibling node, if any.
  
  pe_resource_node_t* {.importc, impresourcesHdr.} = pe_resource_node

  pe_resources_t* {.bycopy, importc, impresourcesHdr.} = object
    err*: pe_err_e
    resource_base_ptr*: pointer  ##   A pointer to the beggining of the IMAGE_RESOURCE_DIRECTORY.
    root_node*: ptr pe_resource_node_t  ##   A pointer to the beggining of the IMAGE_RESOURCE_DIRECTORY.
  
  pe_resource_entry_info_t* {.bycopy, importc, impresourcesHdr.} = object
    name*: cstring
    `type`*: ResourceType
    extension*: cstring
    dir_name*: cstring

  pe_resource_node_predicate_fn* {.importc, impresourcesHdr.} = proc (
      node: ptr pe_resource_node_t): bool {.cdecl.}

  pe_resource_node_search_result_item* {.bycopy, impresourcesHdr,
      importc: "struct pe_resource_node_search_result_item".} = object
    node*: ptr pe_resource_node_t
    next*: ptr pe_resource_node_search_result_item

  pe_resource_node_search_result_item_t* {.importc, impresourcesHdr.} = pe_resource_node_search_result_item

  pe_resource_node_search_result_t* {.bycopy, importc, impresourcesHdr.} = object
    count*: uint
    items*: ptr pe_resource_node_search_result_item_t

# proc pe_resources_dealloc*(obj: ptr pe_resources_t) {.importc, cdecl,
#     impresourcesHdr.}
