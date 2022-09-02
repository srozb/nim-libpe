# nim-libpe

Nim rewrite of [merces/libpe](https://github.com/merces/libpe/) PE library.

This library is used by my PE multitool [Peni](https://github.com/srozb/peni).

## Usage

Minimal working example based on the original one from Author's GH readme, would be:

```nim

import libpe
import libpe/error

var ctx: pe_ctx_t

assert pe_load_file(addr ctx, "path_to_file".cstring) == LIBPE_E_OK
assert pe_parse(addr ctx) == LIBPE_E_OK
assert pe_is_pe(addr ctx)

echo $ctx.pe.entrypoint
```

For more info consult the test file. 
