type
  IMAGE_DOS_HEADER* {.bycopy, importc, header: "hdr_dos.h".} = object
    e_magic*: uint16
    e_cblp*: uint16
    e_cp*: uint16
    e_crlc*: uint16
    e_cparhdr*: uint16
    e_minalloc*: uint16
    e_maxalloc*: uint16
    e_ss*: uint16
    e_sp*: uint16
    e_csum*: uint16
    e_ip*: uint16
    e_cs*: uint16
    e_lfarlc*: uint16
    e_ovno*: uint16
    e_res*: array[4, uint16]
    e_oemid*: uint16
    e_oeminfo*: uint16
    e_res2*: array[10, uint16]
    e_lfanew*: uint32  ## sizeof(IMAGE_DOS_HEADER) + size of MS-DOS stub
