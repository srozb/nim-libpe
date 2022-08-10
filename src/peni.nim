import libpe

var ctx: pe_ctx_t
var err = pe_load_file(addr ctx, "tests/test.bin".cstring)
err = pe_parse(addr ctx)

echo "PE Loaded: " & $pe_is_pe(addr ctx)