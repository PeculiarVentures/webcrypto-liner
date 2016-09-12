# webcrypto-liner

A polyfill for WebCrypto that "smooths out" the rough-edges in existing User Agent implementations.

Though WebCrypto is well [supported accross browsers](http://caniuse.com/cryptography), several browsers still have prefixed and buggy implementations. Additionally they do not always support the same algorithms, for example Edge does not support SHA1 or ECC while both Firefox and Chrome do. 

**NOTE**: If your not familiar with how to use the various capabilities of WebCrypto see [this great example  page](https://github.com/diafygi/webcrypto-examples).

`webcrypto-liner` is a wrapper for WebCrypto designed to address these issues, at the same time it was designed to be modular so that it can also be used for testing the addition of new algorithms to WebCrypto in the future.

Intentionally `webcrypto-liner` does not implement any cryptography though it does consume libraries that does. We strongly recomend you read "[What’s wrong with in-browser cryptography?](https://tonyarcieri.com/whats-wrong-with-webcrypto)" before using this library.

The libraries `webcrypto-liner` relies on include:

| Package                                                    | Description                                                                            | Size   | Optional    |
|------------------------------------------------------------|----------------------------------------------------------------------------------------|--------|-------------|
| [asmcrypto.js](https://github.com/vibornoff/asmcrypto.js/) | JavaScript implementation of popular cryptographic utilities with performance in mind. | 131 KB | Yes |
| [elliptic](https://github.com/indutny/elliptic)            | Fast Elliptic Curve Cryptography in plain javascript                                   | 130 KB | Yes  |
| [webcrypto-core](https://github.com/PeculiarVentures/webcrypto-core)            | A input validation layer for WebCrypto polyfills                 | 31 KB | No  |


`webcrypto-liner` will always try to use a native implementation of webcrypto, or a prefixed version of webcrypto, before it falls back to a Javascript implementation of a given algorithm. We have no control over the corresponding implementation and what it does, for example it may not use `window.crypto.getRandomValues` even if it is available and the mechanism it uses to gather randomness may be both insecure and weak.

We have done no security review or take a position on the security of these third-party libraries. **YOU HAVE BEEN WARNED**.

To keep `webcrypto-liner` as small as possible (right now it is ~11kb without dependencies). Additionally it was designed to be modular, so if you do not need ECC support, do not include `elliptic` as a dependency and it will not be loaded.

If you do not load any of the dependencies that provide cryptographic implementations `webcrypto-liner` will work as an interopanility layer, very similar to [webcrypto-shim](https://github.com/vibornoff/webcrypto-shim).

`webcrypto-liner` supports the following algorithms and key lengths:

| Capability                | Details                                       |
|---------------------------|-----------------------------------------------|
| Encryption/Decryption     | RSA-OAEP, RSA-PKCSv1_15, AES-CBC, and AES-GCM |
| Sign/Verify               | RSA-PSS, RSA-PKCSv1.15, and ECDSA             |
| Hash                      | SHA-1, SHA-224, SHA-256, and SHA-384          |
| Derive Key/Bits           | ECDH                                          |
| Keywrap                   | AES-GCM                                       |
| ECC Curves                | P-256, P-384, and  P-512                      |
| RSA Key Lengths           | 1024, 2048, 3072, and 4096                    |
| AES Key Lengths           | 128, 192 and 256                              |


## Important
This library is not ready for consumption, we have more work to do, including samples, amongst other things.

## Dependencies
typescript
```
npm install typescript --global
```

## Compilation 
Compile the source code using the following command:
```
tsc
```
Compile the source code with declaration using the next command:
```
tsc --declaration
```
