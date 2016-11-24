# webcrypto-liner
[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/webcrypto-liner/master/LICENSE)
[![npm version](https://badge.fury.io/js/webcrypto-liner.svg)](https://badge.fury.io/js/webcrypto-liner)

[![NPM](https://nodei.co/npm-dl/webcrypto-liner.png?months=2&height=2)](https://nodei.co/npm/webcrypto-liner/)


A polyfill for WebCrypto that "smooths out" the rough-edges in existing User Agent implementations.

Though WebCrypto is well [supported across browsers](http://caniuse.com/cryptography), several browsers still have prefixed and buggy implementations. Additionally, they do not always support the same algorithms, for example, Edge does not support SHA1 or ECC while both Firefox and Chrome do. 

**NOTE**: If you are not familiar with how to use the various capabilities of WebCrypto see [this great example  page](https://github.com/diafygi/webcrypto-examples).

`webcrypto-liner` is a wrapper for WebCrypto designed to address these issues, at the same time it was designed to be modular so that it can also be used for testing the addition of new algorithms to WebCrypto in the future.

Intentionally `webcrypto-liner` does not implement any cryptography though it does consume libraries that do. We strongly recommend you read "[What’s wrong with in-browser cryptography?](https://tonyarcieri.com/whats-wrong-with-webcrypto)" before using this library.

The libraries `webcrypto-liner` relies on include:

| Package                                                    | Description                                                                            | Size   | Optional    |
|------------------------------------------------------------|----------------------------------------------------------------------------------------|--------|-------------|
| [asmcrypto.js](https://github.com/vibornoff/asmcrypto.js/) | A [performant](https://medium.com/@encryb/comparing-performance-of-javascript-cryptography-libraries-42fb138116f3) JavaScript implementation of popular cryptographic utilities with performance in mind. | 131&#160;KB | Yes |
| [elliptic](https://github.com/indutny/elliptic)            | Fast Elliptic Curve Cryptography in plain javascript                                   | 130&#160;KB | Yes  |
| [webcrypto-core](https://github.com/PeculiarVentures/webcrypto-core)            | A input validation layer for WebCrypto polyfills <sub>1</sub>    | 25&#160;KB | No  |
<sub>1 This library is compiled into webcrypto-liner.</sub>

`webcrypto-liner` will always try to use a native implementation of webcrypto, or a prefixed version of webcrypto, before it falls back to a Javascript implementation of a given algorithm. We have no control over the corresponding implementation and what it does, for example, it may not use `window.crypto.getRandomValues` even if it is available and the mechanism it uses to gather randomness may be both insecure and weak.

We have done no security review or take a position on the security of these third-party libraries. **YOU HAVE BEEN WARNED**.

To keep `webcrypto-liner` as small as possible (right now it is ~11kb without dependencies) it was designed to be modular, so if you do not need ECC support, do not include `elliptic` as a dependency and it will not be loaded.

If you do not load any of the dependencies that provide cryptographic implementations `webcrypto-liner` will work as an interoperability layer, very similar to [webcrypto-shim](https://github.com/vibornoff/webcrypto-shim).

`webcrypto-liner` supports the following algorithms and key lengths:

| Capability                | Details                                       |
|---------------------------|-----------------------------------------------|
| Encryption/Decryption     | RSA-OAEP, AES-CBC, and AES-GCM                |
| Sign/Verify               | RSA-PSS, ~~RSASSA-PKCS1-v1_5,~~ and ECDSA              |
| Hash                      | SHA-1, SHA-224, SHA-256, and SHA-384          |
| Derive Key/Bits           | ECDH                                          |
| Keywrap                   | AES-GCM, AES-CBC                              |
| ECC Curves                | P-256, P-384, and  P-512                      |
| RSA Key Lengths           | 1024, 2048, 3072, and 4096                    |
| AES Key Lengths           | 128, 192 and 256                              |

You can see the `webcrypto-liner` in use in the [`pv-webcrypto-tests` page](https://peculiarventures.github.io/pv-webcrypto-tests/).

## Using

```html
<head>
    <!-- ... -->
    <!-- ... -->
    <!-- promise.js is needed for IE Promise implementation -->
    <script src="https://www.promisejs.org/polyfills/promise-7.0.4.min.js"></script>
    <script src="src/webcrypto-liner.js"></script>
</head>
<body>
    <script> 
        crypto.subtle.generateKey({name: "AES-GCM", length: 192}, true, ["encrypt", "decrypt"])
            .then(function(key){
                return crypto.subtle.encrypt({
                        name: "AES-GCM", 
                        iv: new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]),
                        tagLength: 128
                    }, key, new Uint8Array([1,2,3,4,5]))
            })
            .then(function(enc){
                console.log(new Uint8Array(enc));
            })
            .catch(function(err){
                console.log(err.message); // Chrome throws: 192-bit AES keys are not supported
            })
    </script>
</body>
```


## Dependencies
typescript
```
npm install typescript --global
```

## Installation
The module has been designed to be useful in ES6 and ES5 projects. The default is ES5 with commonjs, to install and build you would run:

```
npm install
npm run build
```

The package also supports rollup and webpack, if you want a ES5 build with Webpack you would use the following commands:

```
npm install
npm run build:webpack
```

If you want a ES2015 build for rollup you would use the following commands:
```
npm install
npm run build:es2015
```


## FAQ
- **Do I need to use a promise library?** - No, not if your browser supports promises.
- **Do I need to include asmcrypto.js?** No, not unless you want to use the algorithms it exposes.
- **Do I need to include elliptic.js?** No, not unless you want to use the algorithms it exposes.
- **How big is the total package?** Right now, if you include all optional dependencies (minfied) the package is ~300 KB, if you include only ECC or only RSA support that is lowered to about 180 KB. Additionally you will see GZIP compression provide about 30% savings above and beyond that. If you use `webcrypto-liner` as just an interopability shim and do not use any of the optional third-party libraries it will be under 44 KB in size.
- **Will it work in Node?** No. It is compiles to pure Javascript but uses the `window` object so it wont work in Node at this time. With some minor changes it should also be able to work in Node also but you really should be using [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl) on Node instead.

## Related
 - [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [pv-webcrypto-tests](https://peculiarventures.github.io/pv-webcrypto-tests)
 - [webcrypto-core](https://peculiarventures.github.io/webcrypto-core)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
