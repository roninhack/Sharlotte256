# Sharlotte256

The fastest SHA256 library ever, powered by SSE4!

Also it is a fully compatible drop-in for OpenSSL, and works even if the user's
computer is not SSE4 compatible.

## Is it really fast?

It's the fastest and the safest! The core code was taken from Bitcoin Core,
which needed a really fast SHA256 function. It's also one of the most carefully
reviewed software on GitHub!

It's a separate library that features Streaming Simd Extensions 4 hashing
code, so projects other than Bitcoin Core could also use it too!

## Usage

### OpenSSL

Before:
```c
#include <openssl/sha.h>
...
SHA256(data, len, result_pointer);
```
After (compatible with old computers):
```c
#include <openssl/sha.h>
#include <Sharlotte256.h>
...
Sha256_func_t Optimal_SHA256 = AutoSHA256Setter(SHA256);
...
Optimal_SHA256(data, len, result_pointer);
```
After (without keeping compatibility):
```c
#include <Sharlotte256.h>
...
Sharlotte256(data, len, result_pointer);
```

Full API description is in [Sharlotte256.h](/Sharlotte256.h).

## Acknowledgements

Thanks to Intel for the SSE4 YASM code of SHA256!

Thanks to Pieter Wuille of Bitcoin Core for transcribing it into inline assembly!
