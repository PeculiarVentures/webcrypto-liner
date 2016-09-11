namespace webcrypto.liner {
    function prepareAlg(alg: AlgorithmIdentifier) {
        let res: Algorithm;
        if (typeof alg === "string")
            res = { name: alg };
        else
            res = alg;
        return res;
    }

    function prepareData(data: CryptoBuffer) {
        let b: ArrayBuffer = (data as ArrayBufferView).buffer || data as ArrayBuffer;
        return new Uint8Array(b);
    }

    export class CryptoSubtle extends Subtle {

        generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey | CryptoKeyPair> {
            const args = arguments;
            let _alg: Algorithm;
            return super.generateKey.apply(this, args)
                .then((d: Uint8Array) => {
                    _alg = prepareAlg(algorithm);
                    return nativeSubtle.generateKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native generateKey for ${_alg.name} doesn't work.`, e.message || "");
                        });
                })
                .then((keys: CryptoKeyPair) => {
                    if (keys) return new Promise(resolve => resolve(keys));
                    let Class: typeof BaseCrypto = null;
                    switch (_alg.name.toLowerCase()) {
                        case AlgorithmNames.EcDSA.toLowerCase():
                        case AlgorithmNames.EcDH.toLowerCase():
                            Class = ec.EcCrypto;
                            break;
                        default:
                            throw new ShimError(ShimError.NOT_SUPPORTED, "generateKey");
                    }
                    return Class.generateKey(_alg, extractable, keyUsages);
                });
        }

        digest(algorithm: AlgorithmIdentifier, data: CryptoBuffer): PromiseLike<ArrayBuffer> {
            const args = arguments;
            let _alg: Algorithm;
            let _data: Uint8Array;
            return super.digest.apply(this, args)
                .then((d: Uint8Array) => {
                    _alg = prepareAlg(algorithm);
                    _data = prepareData(data);

                    return nativeSubtle.digest.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native digest for ${_alg.name} doesn't work.`, e.message || "");
                        });
                })
                .then((digest: ArrayBuffer) => {
                    if (digest) return new Promise(resolve => resolve(digest));
                    return rsa.ShaCrypto.digest(_alg, _data);
                });
        }

        sign(algorithm: AlgorithmIdentifier, key: CryptoKey, data: CryptoBuffer): PromiseLike<ArrayBuffer> {
            const args = arguments;
            let _alg: Algorithm;
            let _data: Uint8Array;
            return super.sign.apply(this, args)
                .then((d: Uint8Array) => {
                    _alg = prepareAlg(algorithm);
                    _data = prepareData(data);

                    return nativeSubtle.digest.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native sign for ${_alg.name} doesn't work.`, e.message || "");
                        });
                })
                .then((signature: ArrayBuffer) => {
                    if (signature) return new Promise(resolve => resolve(signature));
                    let Class: typeof BaseCrypto;
                    switch (_alg.name.toLowerCase()) {
                        case AlgorithmNames.EcDSA.toLowerCase():
                            Class = ec.EcCrypto;
                            break;
                        default:
                            throw new ShimError(ShimError.NOT_SUPPORTED, "sign");
                    }
                    return Class.sign(_alg, key, _data);
                });
        }

        deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
            const args = arguments;
            let _alg: Algorithm;
            return super.deriveBits.apply(this, args)
                .then((bits: ArrayBuffer) => {
                    _alg = prepareAlg(algorithm);

                    try {
                        return nativeSubtle.deriveBits.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                console.warn(`WebCrypto: native deriveBits for ${_alg.name} doesn't work.`, e.message || "");
                            });
                    }
                    catch (e) {
                        // Edge throws error. Don't know Why.
                        console.warn(`WebCrypto: native deriveBits for ${_alg.name} doesn't work.`, e.message || "");
                    }

                })
                .then((bits: ArrayBuffer) => {
                    if (bits) return new Promise(resolve => resolve(bits));
                    let Class: typeof BaseCrypto;
                    switch (_alg.name.toLowerCase()) {
                        case AlgorithmNames.EcDH.toLowerCase():
                            Class = ec.EcCrypto;
                            break;
                        default:
                            throw new ShimError(ShimError.NOT_SUPPORTED, "deriveBits");
                    }
                    return Class.deriveBits(_alg, baseKey, length);
                });
        }

        deriveKey(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            const args = arguments;
            let _alg: Algorithm;
            let _algDerivedKey: Algorithm;
            return super.deriveKey.apply(this, args)
                .then((bits: ArrayBuffer) => {
                    _alg = prepareAlg(algorithm);
                    _algDerivedKey = prepareAlg(derivedKeyType);

                    return nativeSubtle.deriveKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native deriveKey for ${_alg.name} doesn't work.`, e.message || "");
                        });
                })
                .then((key: CryptoKey) => {
                    if (key) return new Promise(resolve => resolve(key));
                    let Class: typeof BaseCrypto;
                    switch (_alg.name.toLowerCase()) {
                        case AlgorithmNames.EcDH.toLowerCase():
                            Class = ec.EcCrypto;
                            break;
                        default:
                            throw new ShimError(ShimError.NOT_SUPPORTED, "deriveBits");
                    }
                    return Class.deriveKey(_alg, baseKey, _algDerivedKey, extractable, keyUsages);
                });
        }

    }
}