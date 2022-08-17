import unittest

import libpe
import libpe/error

import libpe/imports
import libpe/exports
import libpe/hashes
import libpe/hdr_dos
import libpe/hdr_coff
import libpe/sections
import libpe/directories

suite "Testing PE32+ exe":
  var ctx: pe_ctx_t
  var err = pe_load_file(addr ctx, "tests/files/x86exe.bin".cstring)

  test "File Loaded":
    check pe_is_loaded(addr ctx) == true
    check err == LIBPE_E_OK

  test "PE Parse":
    check pe_parse(addr ctx) == LIBPE_E_OK

  test "Filesize":
    check pe_filesize(addr ctx) == 71680

  test "Header type PE32+ (x64)":
    check ctx.pe.optional_hdr.`type` == 0x20b

  test "PE is not dll":
    check pe_is_pe(addr ctx)
    check pe_is_dll(addr ctx) == false

  test "PE Headers":
    var dosHeader = pe_dos(addr ctx)
    check dosHeader.e_magic == 0x5a4d
    check dosHeader.e_lfanew == 0xf8

    var coffHeader = pe_coff(addr ctx)
    check coffHeader.Machine == IMAGE_FILE_MACHINE_AMD64.uint16
    check coffHeader.NumberOfSections == 7
    check coffHeader.TimeDateStamp.Natural == 4215970411

    var optHeader = pe_optional(addr ctx)
    check optHeader.h_64.AddressOfEntryPoint == 0x6890

  test "PE Directories":
    let peDirsCount = pe_directories_count(addr ctx)
    check peDirsCount == 16
    for dirType, dirVal in ctx.directories:
      check dirType == 1
      check dirVal.Size == 700
      check $pe_directory_name(dirType) == "IMAGE_DIRECTORY_ENTRY_IMPORT"
      break  # Check only first directory

  test "PE Sections":
    check pe_sections_count(addr ctx) == 7
    var sec = pe_section_by_name(addr ctx, ".text".cstring)
    check $sec.Name == ".text"
    check sec.VirtualAddress == 4096
    check sec.SizeOfRawData == 27136
    check sec.PointerToRawData == 1024

  test "PE Sections iterator":
    for sec in ctx.sections:
      check sec == pe_section_by_name(addr ctx, sec.Name)

  test "PE Exports":
    let exports = pe_exports(addr ctx)
    check exports.functions_count == 0

  test "PE Entrypoint":
    check ctx.pe.entrypoint == 0x6890

  test "PE Entropy":
    check pe_calculate_entropy_file(addr ctx) == 5.969794543169005

  test "PE Imphash":
    check $pe_imphash(addr ctx, LIBPE_IMPHASH_FLAVOR_PEFILE) == "4db27267734d1576d75c991dc70f68ac"
    
  test "PE Hashing":
    let hSize = pe_hash_recommended_size()
    let sectHashes = pe_get_sections_hash(addr ctx)

    var output = newString(hSize)  # Looks risky
    ## MD5
    output.setLen(32)
    discard pe_hash_raw_data(output.cstring, hSize, "md5".cstring, 
      cast[ptr uint8](ctx.map_addr), ctx.map_size.uint)
    check output == "ef3179d498793bf4234f708d3be28633"

    ## SHA1
    output.setLen(40)
    discard pe_hash_raw_data(output.cstring, hSize, "sha1".cstring, 
      cast[ptr uint8](ctx.map_addr), ctx.map_size.uint)
    check output == "dd399ae46303343f9f0da189aee11c67bd868222"

    ## SHA256
    output.setLen(64)
    discard pe_hash_raw_data(output.cstring, hSize, "sha256".cstring, 
      cast[ptr uint8](ctx.map_addr), ctx.map_size.uint)
    check output == "b53f3c0cd32d7f20849850768da6431e5f876b7bfa61db0aa0700b02873393fa"

    check $sectHashes.sections[0].ssdeep == "768:0s5+Tb76ffBDDwBL/qRzgNReI3fu6MpJ9lw2c9zxZqz3YM:Z8qpnO/qRUNReI3fu6Uw2mTA" # BUG

suite "Testing PE32 dll":
  var ctx: pe_ctx_t
  var err = pe_load_file(addr ctx, "tests/files/x86dll.bin".cstring)

  test "File Loaded":
    check pe_is_loaded(addr ctx) == true
    check err == LIBPE_E_OK

  test "PE Parse":
    check pe_parse(addr ctx) == LIBPE_E_OK

  test "Filesize":
    check pe_filesize(addr ctx) == 290680

  test "Header type PE32":
    check ctx.pe.optional_hdr.`type` == 0x10b

  test "PE is not dll":
    check pe_is_pe(addr ctx)
    check pe_is_dll(addr ctx)

  test "PE Sections":
    check pe_sections_count(addr ctx) == 5

  test "PE Imports":
    let imports = pe_imports(addr ctx)
    check imports.dll_count == 3
    check imports.dlls[0].name == "LIBEAY32.dll"
    check imports.dlls[0].functions_count == 372
    check imports.dlls[1].functions[4].name == "free"
    check imports.dlls[1].functions[4].hint == 1667
    check imports["libeay32.dll"].name == "LIBEAY32.dll"
    check imports["KERNEL32.dll"]["GetLastError"].hint == 592

  test "PE Exports":
    let exports = pe_exports(addr ctx)
    check exports.name == "SSLEAY32.dll"
    check exports.functions_count == 409
    check exports.functions[3].name == "SSL_CTX_add_session"
    check exports.functions[3].address == 158208
    check exports["ssl_ctx_add_session"].address == 158208

  test "PE Entrypoint":
    check ctx.pe.entrypoint == 0x323b7

  test "PE Entropy":
    check pe_calculate_entropy_file(addr ctx) == 6.459661550366066

  test "TLS Callback":
    check pe_get_tls_callback(addr ctx) == -2  # TODO: improve test case

  test "PE Hashing":
    check $pe_imphash(addr ctx, LIBPE_IMPHASH_FLAVOR_PEFILE) == "424359274c5f83c7008c38ebd2508fee"

    let headerHashes = pe_get_headers_hashes(addr ctx)
    check $headerHashes.dos.md5 == "a83927f73eea9f5610e0bab5d44f05c5"
    check $headerHashes.coff.md5 == "c03ffb62fdd614762dfde4b31bfe2ff9"
    check $headerHashes.optional.md5 == "f42701098bb164092d48f12dfe127290"

    let sectHashes = pe_get_sections_hash(addr ctx)
    check $sectHashes.sections[0].ssdeep == "6144:8LFThsrlPqhXPXpwiKQQg9L8YMcoIyHJPNlK9//ualAcQYLUIaGdY7Y1XiRdQMJ:mFThsrlPqhXPXpwiHQg9L8xcoIyHJfK"  # BUG
