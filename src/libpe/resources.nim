import dir_resources
import error
import def_enums

defineEnum(pe_resource_level_e)
defineEnum(pe_resource_node_type_e)

type
  Union_resourcesh1* {.union, bycopy.} = object
    raw_ptr*: pointer  ##   We are allowed to rely on type-punning in C99, but not in C++.
    resourceDirectory*: ptr IMAGE_RESOURCE_DIRECTORY  ##   type == LIBPE_RDT_RESOURCE_DIRECTORY
    directoryEntry*: ptr IMAGE_RESOURCE_DIRECTORY_ENTRY  ##   type == LIBPE_RDT_DIRECTORY_ENTRY
    dataString*: ptr IMAGE_RESOURCE_DATA_STRING_U  ##   type == LIBPE_RDT_DATA_STRING
    dataEntry*: ptr IMAGE_RESOURCE_DATA_ENTRY  ##   type == LIBPE_RDT_DATA_ENTRY
  
  pe_resource_node* {.bycopy.} = object
    depth*: uint16
    dirLevel*: uint32  ##   pe_resouces_level_e
    `type`*: pe_resource_node_type_e  ##   pe_resouces_level_e
    name*: cstring
    raw*: Union_resourcesh1
    parentNode*: ptr pe_resource_node  ##   Points to the parent node, if any.
    childNode*: ptr pe_resource_node  ##   Points to the 1st child node, if any.
    nextNode*: ptr pe_resource_node  ##   Points to the next sibling node, if any.
  
  pe_resource_node_t* = pe_resource_node

  pe_resources_t* {.bycopy.} = object
    err*: pe_err_e
    resource_base_ptr*: pointer  ##   A pointer to the beggining of the IMAGE_RESOURCE_DIRECTORY.
    root_node*: ptr pe_resource_node_t  ##   A pointer to the beggining of the IMAGE_RESOURCE_DIRECTORY.
  
  pe_resource_entry_info_t* {.bycopy.} = object
    name*: cstring
    `type`*: ResourceType
    extension*: cstring
    dir_name*: cstring

  pe_resource_node_predicate_fn* = proc (node: ptr pe_resource_node_t): bool {.cdecl.}

  pe_resource_node_search_result_item* {.bycopy.} = object
    node*: ptr pe_resource_node_t
    next*: ptr pe_resource_node_search_result_item

  pe_resource_node_search_result_item_t* = pe_resource_node_search_result_item

  pe_resource_node_search_result_t* {.bycopy.} = object
    count*: uint
    items*: ptr pe_resource_node_search_result_item_t

const
  LIBPE_RDT_LEVEL1* = (1).pe_resource_level_e
  LIBPE_RDT_LEVEL2* = (2).pe_resource_level_e
  LIBPE_RDT_LEVEL3* = (3).pe_resource_level_e
  LIBPE_RDT_RESOURCE_DIRECTORY* = (1).pe_resource_node_type_e
  LIBPE_RDT_DIRECTORY_ENTRY* = (2).pe_resource_node_type_e
  LIBPE_RDT_DATA_STRING* = (3).pe_resource_node_type_e
  LIBPE_RDT_DATA_ENTRY* = (4).pe_resource_node_type_e

  g_resource_dataentry_info_table*: seq[pe_resource_entry_info_t] = @[
    pe_resource_entry_info_t(name:"???_0", `type`:0.ResourceType, extension:".0", dir_name:"_0"),
    pe_resource_entry_info_t(name:"RT_CURSOR", `type`:RT_CURSOR, extension:".cur", dir_name:"cursors"),
    pe_resource_entry_info_t(name:"RT_BITMAP", `type`:RT_BITMAP, extension:".bmp", dir_name:"bitmaps"),
    pe_resource_entry_info_t(name:"RT_ICON", `type`:RT_ICON, extension:".ico", dir_name:"icons"),
    pe_resource_entry_info_t(name:"RT_MENU", `type`:RT_MENU, extension:".rc", dir_name:"menus"),
    pe_resource_entry_info_t(name:"RT_DIALOG", `type`:RT_DIALOG, extension:".dlg", dir_name:"dialogs"),
    pe_resource_entry_info_t(name:"RT_STRING", `type`:RT_STRING, extension:".rc", dir_name:"strings"),
    pe_resource_entry_info_t(name:"RT_FONTDIR", `type`:RT_FONTDIR, extension:".fnt", dir_name:"fontdirs"),
    pe_resource_entry_info_t(name:"RT_FONT", `type`:RT_FONT, extension:".fnt", dir_name:"fonts"),
    pe_resource_entry_info_t(name:"RT_ACCELERATOR", `type`:RT_ACCELERATOR, extension:".rc", dir_name:"accelerators"),
    pe_resource_entry_info_t(name:"RT_RCDATA", `type`:RT_RCDATA, extension:".rc", dir_name:"rcdatas"),
    pe_resource_entry_info_t(name:"RT_MESSAGETABLE", `type`:RT_MESSAGETABLE, extension:".mc", dir_name:"messagetables"),
    pe_resource_entry_info_t(name:"RT_GROUP_CURSOR", `type`:RT_GROUP_CURSOR, extension:".cur", dir_name:"groupcursors"),
    pe_resource_entry_info_t(name:"???_13", `type`:13.ResourceType, extension:".13", dir_name:"_13"),
    pe_resource_entry_info_t(name:"RT_GROUP_ICON", `type`:RT_GROUP_ICON, extension:".ico", dir_name:"groupicons"),
    pe_resource_entry_info_t(name:"???_15", `type`:15.ResourceType, extension:".15", dir_name:"_15"),
    pe_resource_entry_info_t(name:"RT_VERSION", `type`:RT_VERSION, extension:".rc", dir_name:"versions"),
    pe_resource_entry_info_t(name:"RT_DLGINCLUDE", `type`:RT_DLGINCLUDE, extension:".rc", dir_name:"dlgincludes"),
    pe_resource_entry_info_t(name:"???_18", `type`:18.ResourceType, extension:".18", dir_name:"_18"),
    pe_resource_entry_info_t(name:"RT_PLUGPLAY", `type`:RT_PLUGPLAY, extension:".rc", dir_name:"plugplays"),
    pe_resource_entry_info_t(name:"RT_VXD", `type`:RT_VXD, extension:".rc", dir_name:"vxds"),
    pe_resource_entry_info_t(name:"RT_ANICURSOR", `type`:RT_ANICURSOR, extension:".rc", dir_name:"anicursors"),
    pe_resource_entry_info_t(name:"RT_ANIICON", `type`:RT_ANIICON, extension:".rc", dir_name:"aniicons"),
    pe_resource_entry_info_t(name:"RT_HTML", `type`:RT_HTML, extension:".html", dir_name:"htmls"),
    pe_resource_entry_info_t(name:"RT_MANIFEST", `type`:RT_MANIFEST, extension:".xml", dir_name:"manifests"),
    pe_resource_entry_info_t(name:"RT_DLGINIT", `type`:RT_DLGINIT, extension:".rc", dir_name:"dlginits"),
    pe_resource_entry_info_t(name:"RT_TOOLBAR", `type`:RT_TOOLBAR, extension:".rc", dir_name:"toolbars"),
  ]

# proc pe_resources_dealloc*(obj: ptr pe_resources_t) {.importc, cdecl,
#     impresourcesHdr.}
