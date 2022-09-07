proc `+`*(a: pointer, s: Natural): pointer = cast[pointer](cast[int](a) + s)

converter ptrToPtrUint*(a: pointer): ptr uint = cast[ptr uint](a)
converter ptrToPtrUint32*(a: pointer): ptr uint32 = cast[ptr uint32](a)