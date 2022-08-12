# nim-libpe

Nim wrapper for [merces/libpe](https://github.com/merces/libpe/) PE library.

Created by Nimterop to be used by [Peni - Nim PE parsing tool](https://github.com/srozb/peni).

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

## Build 

nim c --passL:"-lpe"
