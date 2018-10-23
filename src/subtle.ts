// Core
import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import * as core from "webcrypto-core";
import { PrepareAlgorithm, PrepareData } from "webcrypto-core";

// Base
import { nativeSubtle } from "./init";
import { Crypto } from "./crypto";
import { LinerError } from "./error";
import { string2buffer, buffer2string, concat, Browser, BrowserInfo, assign, warn } from "./helper";
import { CryptoKey, CryptoKeyPair } from "./key";

// Crypto
import { AesCrypto } from "./aes/crypto";
import { ShaCrypto } from "./sha/crypto";
import { RsaCrypto } from "./rsa/crypto";
import { EcCrypto } from "./ec/crypto";

declare type IE = any;

const keys: Array<{ key: CryptoKey, hash: Algorithm }> = [];

function PrepareKey(key: CryptoKey, subtle: typeof BaseCrypto) {
    return Promise.resolve()
        .then(() => {
            if (key.key) {
                return key;
            }
            if (!key.extractable) {
                throw new LinerError("'key' is Native CryptoKey. It can't be converted to JS CryptoKey");
            } else {
                const crypto = new Crypto();
                return crypto.subtle.exportKey("jwk", key)
                    .then((jwk: any) => {
                        let alg = GetHashAlgorithm(key);
                        if (alg) {
                            alg = assign(alg, key.algorithm);
                        }
                        return subtle.importKey("jwk", jwk, alg as any, true, key.usages);
                    });
            }
        });
}

export class SubtleCrypto extends core.SubtleCrypto {

    public generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]) {
        const args = arguments;
        let alg: Algorithm;
        return super.generateKey.apply(this, args)
            .then((d: Uint8Array) => {
                alg = PrepareAlgorithm(algorithm);

                const browser = BrowserInfo();
                if (
                    (browser.name === Browser.Edge && alg.name.toUpperCase() === AlgorithmNames.AesGCM) ||
                    // Don't do AES-GCM key generation, because Edge throws errors on GCM encrypt, decrypt, wrapKey, unwrapKey
                    CheckAppleRsaOAEP(alg.name)
                    // Don't use native generateKey for RSA-OAEP on Safari before v11
                    // https://github.com/PeculiarVentures/webcrypto-liner/issues/53
                ) {
                    return;
                }

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.generateKey.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native generateKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native generateKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((generatedKeys: CryptoKey | CryptoKeyPair) => {
                if (generatedKeys) {
                    let promise = Promise.resolve(generatedKeys);

                    /**
                     * Safari issue
                     * https://github.com/PeculiarVentures/webcrypto-liner/issues/39
                     * if public key cannot be exported in correct JWK format, then run new generateKey
                     */
                    if (BrowserInfo().name === Browser.Safari &&
                        (
                            alg.name.toUpperCase() === AlgorithmNames.EcDH.toUpperCase() ||
                            alg.name.toUpperCase() === AlgorithmNames.EcDSA.toUpperCase()
                        )
                    ) {
                        const pubKey = (generatedKeys as CryptoKeyPair).publicKey;
                        promise = promise.then(() => {
                            return this.exportKey("jwk", pubKey)
                                .then((jwk: any) => {
                                    return this.exportKey("spki", pubKey)
                                        .then((spki: ArrayBuffer) => {
                                            const x = Base64Url.decode(jwk.x);
                                            const y = Base64Url.decode(jwk.y);

                                            const len = x.length + y.length;
                                            const spkiBuf = new Uint8Array(spki);
                                            for (let i = 0; i < len; i++) {
                                                const spkiByte = spkiBuf[spkiBuf.length - i - 1];
                                                let pointByte: number;
                                                if (i < y.length) {
                                                    pointByte = y[y.length - i - 1];
                                                } else {
                                                    pointByte = x[x.length + y.length - i - 1];
                                                }
                                                if (spkiByte !== pointByte) {
                                                    // regenerate new key
                                                    warn("WebCrypto: EC key has wrong public key JWK. Key pair will be recreated");
                                                    return this.generateKey(algorithm, extractable, keyUsages);
                                                }
                                            }
                                            return generatedKeys;
                                        });
                                });
                        });
                    }

                    return promise.then((keys2: any) => {
                        FixCryptoKeyUsages(keys2, keyUsages);
                        SetHashAlgorithm(alg, keys2);
                        return keys2;
                    });
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                    case AlgorithmNames.RsaPSS.toLowerCase():
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
                }
                return Class.generateKey(alg, extractable, keyUsages);
            });
    }

    public digest(algorithm: AlgorithmIdentifier, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let alg: Algorithm;
        let dataBytes: Uint8Array;
        return super.digest.apply(this, args)
            .then((d: Uint8Array) => {
                alg = PrepareAlgorithm(algorithm);
                dataBytes = PrepareData(data, "data");

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.digest.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native digest for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native digest for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((digest: ArrayBuffer) => {
                if (digest) {
                    return digest;
                }
                return ShaCrypto.digest(alg, dataBytes);
            });
    }

    public sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let alg: Algorithm;
        let dataBytes: Uint8Array;
        return super.sign.apply(this, args)
            .then((d: Uint8Array) => {
                alg = PrepareAlgorithm(algorithm as string);
                dataBytes = PrepareData(data, "data");

                const alg2 = GetHashAlgorithm(key);
                if (alg2) {
                    args[0] = assign(alg, alg2);
                }

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.sign.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native sign for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native sign for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((signature: ArrayBuffer) => {
                if (signature) {
                    return signature;
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaSSA.toLowerCase():
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
                }
                return PrepareKey(key, Class)
                    .then((preparedKey) => Class.sign(alg, preparedKey, dataBytes));
            });
    }

    public verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: BufferSource, data: BufferSource): PromiseLike<boolean> {
        const args = arguments;
        let alg: Algorithm;
        let signatureBytes: Uint8Array;
        let dataBytes: Uint8Array;
        return super.verify.apply(this, args)
            .then((d: boolean) => {
                alg = PrepareAlgorithm(algorithm as string);
                signatureBytes = PrepareData(signature, "data");
                dataBytes = PrepareData(data, "data");

                const alg2 = GetHashAlgorithm(key);
                if (alg2) {
                    args[0] = assign(alg, alg2);
                }
                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.verify.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native verify for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native verify for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((result: boolean) => {
                if (typeof result === "boolean") {
                    return result;
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaSSA.toLowerCase():
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
                }
                return PrepareKey(key, Class)
                    .then((preparedKey) => Class.verify(alg, preparedKey, signatureBytes, dataBytes));
            });
    }

    public deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let alg: Algorithm;
        return super.deriveBits.apply(this, args)
            .then((bits: ArrayBuffer) => {
                alg = PrepareAlgorithm(algorithm);

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.deriveBits.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native deriveBits for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        // Edge throws error. Don't know Why.
                        warn(`WebCrypto: native deriveBits for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }

            })
            .then((bits: ArrayBuffer) => {
                if (bits) {
                    return bits;
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        Class = EcCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "deriveBits");
                }
                return Class.deriveBits(alg, baseKey, length);
            });
    }

    public deriveKey(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        const args = arguments;
        let alg: Algorithm;
        let algDerivedKey: Algorithm;
        return super.deriveKey.apply(this, args)
            .then((bits: ArrayBuffer) => {
                alg = PrepareAlgorithm(algorithm);
                algDerivedKey = PrepareAlgorithm(derivedKeyType);

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.deriveKey.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native deriveKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        // Edge doesn't go to catch of Promise
                        warn(`WebCrypto: native deriveKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((key: CryptoKey) => {
                if (key) {
                    FixCryptoKeyUsages(key, keyUsages);
                    return key;
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        Class = EcCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "deriveBits");
                }
                return Class.deriveKey(alg, baseKey, algDerivedKey, extractable, keyUsages);
            });
    }

    public encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let alg: Algorithm;
        let dataBytes: Uint8Array;
        return super.encrypt.apply(this, args)
            .then((bits: ArrayBuffer) => {
                alg = PrepareAlgorithm(algorithm);
                dataBytes = PrepareData(data, "data");

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.encrypt.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native 'encrypt' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native 'encrypt' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((msg: any) => {
                if (msg) {
                    if (BrowserInfo().name === Browser.IE &&
                        alg.name.toUpperCase() === AlgorithmNames.AesGCM &&
                        msg.ciphertext) {
                        // Concatenate values in IE
                        const buf = new Uint8Array(msg.ciphertext.byteLength + msg.tag.byteLength);
                        let count = 0;
                        new Uint8Array(msg.ciphertext).forEach((v: number) => buf[count++] = v);
                        new Uint8Array(msg.tag).forEach((v: number) => buf[count++] = v);
                        msg = buf.buffer;
                    }
                    return Promise.resolve(msg);
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "encrypt");
                }
                return PrepareKey(key, Class)
                    .then((preparedKey) => Class.encrypt(alg, preparedKey, dataBytes));
            });
    }

    public decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let alg: Algorithm;
        let dataBytes: Uint8Array;
        return super.decrypt.apply(this, args)
            .then((bits: ArrayBuffer) => {
                alg = PrepareAlgorithm(algorithm);
                dataBytes = PrepareData(data, "data");

                let dataBytes2: any = dataBytes;
                if (BrowserInfo().name === Browser.IE &&
                    alg.name.toUpperCase() === AlgorithmNames.AesGCM) {
                    // Split buffer
                    const len = dataBytes.byteLength - ((alg as any).tagLength / 8);
                    dataBytes2 = {
                        ciphertext: dataBytes.buffer.slice(0, len),
                        tag: dataBytes.buffer.slice(len, dataBytes.byteLength),
                    };
                }

                if (!key.key) {
                    return nativeSubtle!.decrypt.call(nativeSubtle, alg, key, dataBytes2);
                } else {
                    let Class: typeof BaseCrypto;
                    switch (alg.name.toLowerCase()) {
                        case AlgorithmNames.AesECB.toLowerCase():
                        case AlgorithmNames.AesCBC.toLowerCase():
                        case AlgorithmNames.AesGCM.toLowerCase():
                            Class = AesCrypto;
                            break;
                        case AlgorithmNames.RsaOAEP.toLowerCase():
                            Class = RsaCrypto;
                            break;
                        default:
                            throw new LinerError(LinerError.NOT_SUPPORTED, "decrypt");
                    }
                    return Class.decrypt(alg, key, dataBytes);
                }
            });
    }

    public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let alg: Algorithm;
        return super.wrapKey.apply(this, args)
            .then((bits: ArrayBuffer) => {
                alg = PrepareAlgorithm(wrapAlgorithm);

                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.wrapKey.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native 'wrapKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native 'wrapKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((msg: ArrayBuffer) => {
                if (msg) {
                    return msg;
                }
                let Class: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "wrapKey");
                }
                return Class.wrapKey(format, key, wrappingKey, alg);
            });
    }

    public unwrapKey(format: string, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        const args = arguments;
        let alg: Algorithm;
        let algKey: Algorithm;
        let dataBytes: Uint8Array;
        return super.unwrapKey.apply(this, args)
            .then((bits: ArrayBuffer) => {
                alg = PrepareAlgorithm(unwrapAlgorithm);
                algKey = PrepareAlgorithm(unwrappedKeyAlgorithm);
                dataBytes = PrepareData(wrappedKey, "wrappedKey");

                if (!unwrappingKey.key) {
                    return nativeSubtle!.unwrapKey.apply(nativeSubtle, args)
                        .catch((err: Error) => {
                            // Edge throws errors on unwrapKey native functions
                            // Use custom unwrap function
                            return this.decrypt(alg, unwrappingKey, wrappedKey)
                                .then((decryptedData) => {
                                    let preparedData: JsonWebKey | BufferSource;
                                    if (format === "jwk") {
                                        preparedData = JSON.parse(buffer2string(new Uint8Array(decryptedData)));
                                    } else {
                                        preparedData = decryptedData;
                                    }
                                    return this.importKey(format, preparedData, algKey, extractable, keyUsages);
                                });
                        })
                        .then((k: CryptoKey) => {
                            if (k) {
                                FixCryptoKeyUsages(k, keyUsages);
                                return k;
                            }
                        })
                        .catch((error: Error) => {
                            console.error(error);
                            throw new Error("Cannot unwrap key from incoming data");
                        });
                } else {
                    let Class: typeof BaseCrypto;
                    switch (alg.name.toLowerCase()) {
                        case AlgorithmNames.AesECB.toLowerCase():
                        case AlgorithmNames.AesCBC.toLowerCase():
                        case AlgorithmNames.AesGCM.toLowerCase():
                            Class = AesCrypto;
                            break;
                        case AlgorithmNames.RsaOAEP.toLowerCase():
                            Class = RsaCrypto;
                            break;
                        default:
                            throw new LinerError(LinerError.NOT_SUPPORTED, "unwrapKey");
                    }
                    return Class.unwrapKey(format, dataBytes, unwrappingKey, alg, algKey, extractable, keyUsages);
                }
            });
    }

    public exportKey(format: string, key: CryptoKey) {
        const args = arguments;
        return super.exportKey.apply(this, args)
            .then(() => {
                if (nativeSubtle) {
                    try {
                        return nativeSubtle!.exportKey.apply(nativeSubtle, args)
                            .catch((e: Error) => {
                                warn(`WebCrypto: native 'exportKey' for ${key.algorithm.name} doesn't work.`, e && e.message || "Unknown message");
                            });
                    } catch (e) {
                        warn(`WebCrypto: native 'exportKey' for ${key.algorithm.name} doesn't work.`, e && e.message || "Unknown message");
                    }
                }
            })
            .then((msg: any) => {
                if (msg) {
                    if (format === "jwk" && msg instanceof ArrayBuffer) {
                        msg = buffer2string(new Uint8Array(msg));
                        msg = JSON.parse(msg);
                    }
                    let alg = GetHashAlgorithm(key);
                    if (!alg) {
                        alg = assign({}, key.algorithm);
                    }
                    FixExportJwk(msg, alg, key.usages);
                    return Promise.resolve(msg);
                }
                if (!key.key) {
                    throw new LinerError("Cannot export native CryptoKey from JS implementation");
                }
                let Class: typeof BaseCrypto;
                switch (key.algorithm.name!.toLowerCase()) {
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    case AlgorithmNames.EcDH.toLowerCase():
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaSSA.toLowerCase():
                    case AlgorithmNames.RsaPSS.toLowerCase():
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name!.toLowerCase());
                }
                return Class.exportKey(format, key);
            });
    }

    public async importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]) {
        const args = { format, keyData, algorithm, extractable, keyUsages };
        let dataAny: any;
        const bits = await super.importKey.apply(this, args);

        const alg: Algorithm = PrepareAlgorithm(algorithm);
        dataAny = keyData;

        // Fix: Safari
        const browser = BrowserInfo();
        if (format === "jwk" && (
            (browser.name === Browser.Safari && !/^11/.test(browser.version)) ||
            browser.name === Browser.IE)) {
            // Converts JWK to ArrayBuffer
            if (BrowserInfo().name === Browser.IE) {
                keyData = assign({}, keyData);
                FixImportJwk(keyData);
            }
            args.keyData = string2buffer(JSON.stringify(keyData)).buffer;
        }
        // End: Fix
        if (ArrayBuffer.isView(keyData)) {
            dataAny = PrepareData(keyData, "keyData");
        }

        if (CheckAppleRsaOAEP(alg.name)) {
            // Don't use native importKey for RSA-OAEP on Safari before v11
            // https://github.com/PeculiarVentures/webcrypto-liner/issues/53
            return;
        }

        let k: CryptoKey | undefined;
        if (nativeSubtle) {
            try {
                k = await nativeSubtle!.importKey.apply(nativeSubtle, args);
            } catch (e) {
                warn(`WebCrypto: native 'importKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
            }
        }
        if (k) {
            SetHashAlgorithm(alg, k);
            FixCryptoKeyUsages(k, keyUsages);
            return Promise.resolve(k);
        }
        let Class: typeof BaseCrypto;
        switch (alg.name.toLowerCase()) {
            case AlgorithmNames.AesECB.toLowerCase():
            case AlgorithmNames.AesCBC.toLowerCase():
            case AlgorithmNames.AesGCM.toLowerCase():
                Class = AesCrypto;
                break;
            case AlgorithmNames.EcDH.toLowerCase():
            case AlgorithmNames.EdDSA.toLowerCase():
            case AlgorithmNames.EcDSA.toLowerCase():
                Class = EcCrypto;
                break;
            case AlgorithmNames.RsaSSA.toLowerCase():
            case AlgorithmNames.RsaPSS.toLowerCase():
            case AlgorithmNames.RsaOAEP.toLowerCase():
                Class = RsaCrypto;
                break;
            default:
                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
        }
        return Class.importKey(format, dataAny, alg, extractable, keyUsages);
    }
}

// save hash alg for RSA keys
function SetHashAlgorithm(alg: Algorithm, key: CryptoKey | CryptoKeyPair) {
    if ((BrowserInfo().name === Browser.IE || BrowserInfo().name === Browser.Edge || BrowserInfo().name === Browser.Safari) && /^rsa/i.test(alg.name)) {
        if ((key as CryptoKeyPair).privateKey) {
            keys.push({ hash: (alg as any).hash, key: (key as CryptoKeyPair).privateKey });
            keys.push({ hash: (alg as any).hash, key: (key as CryptoKeyPair).publicKey });
        } else {
            keys.push({ hash: (alg as any).hash, key: key as CryptoKey });
        }
    }
}

// fix hash alg for rsa key
function GetHashAlgorithm(key: CryptoKey): Algorithm | null {
    let alg: Algorithm | null = null;
    keys.some((item) => {
        if (item.key === key) {
            alg = assign({}, key.algorithm, { hash: item.hash });
            return true;
        }
        return false;
    });
    return alg;
}

// Extend Uint8Array for IE
if (!Uint8Array.prototype.forEach) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    (Uint8Array as any).prototype.forEach = function (cb: (value: number, index: number, array: Uint8Array) => void) {
        for (let i = 0; i < this.length; i++) {
            cb(this[i], i, this);
        }
    };
}
if (!Uint8Array.prototype.slice) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    (Uint8Array as any).prototype.slice = function (start: number, end: number) {
        return new Uint8Array(this.buffer.slice(start, end));
    };
}
if (!Uint8Array.prototype.filter) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    (Uint8Array as any).prototype.filter = function (cb: (value: number, index: number, array: Uint8Array) => boolean) {
        const buf: number[] = [];
        for (let i = 0; i < this.length; i++) {
            if (cb(this[i], i, this)) {
                buf.push(this[i]);
            }
        }
        return new Uint8Array(buf);
    };
}

function FixCryptoKeyUsages(key: CryptoKey | CryptoKeyPair, keyUsages: string[]) {
    const keyArray: CryptoKey[] = [];
    if ((key as CryptoKeyPair).privateKey) {
        keyArray.push((key as CryptoKeyPair).privateKey);
        keyArray.push((key as CryptoKeyPair).publicKey);
    } else {
        keyArray.push(key as CryptoKey);
    }
    keyArray.forEach((k: any) => {
        if ("keyUsage" in k) {
            k.usages = k.keyUsage || [];
            // add usages
            if (!k.usages.length) {
                ["verify", "encrypt", "wrapKey"]
                    .forEach((usage) => {
                        if (keyUsages.indexOf(usage) > -1 && (k.type === "public" || k.type === "secret")) {
                            k.usages.push(usage);
                        }
                    });
                ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"]
                    .forEach((usage) => {
                        if (keyUsages.indexOf(usage) > -1 && (k.type === "private" || k.type === "secret")) {
                            k.usages.push(usage);
                        }
                    });
            }
        }
    });
}

function FixExportJwk(jwk: any, alg: any, keyUsages: string[]) {
    if (alg && BrowserInfo().name === Browser.IE) {
        // ext
        if ("extractable" in jwk) {
            jwk.ext = jwk.extractable;
            delete jwk.extractable;
        }
        // add alg
        let CryptoClass: AlgorithmConverter | null = null;
        switch (alg.name.toUpperCase()) {
            case AlgorithmNames.RsaOAEP.toUpperCase():
            case AlgorithmNames.RsaPSS.toUpperCase():
            case AlgorithmNames.RsaSSA.toUpperCase():
                CryptoClass = RsaCrypto;
                break;
            case AlgorithmNames.AesECB.toUpperCase():
            case AlgorithmNames.AesCBC.toUpperCase():
            case AlgorithmNames.AesGCM.toUpperCase():
                CryptoClass = AesCrypto;
                break;
            default:
                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toUpperCase());
        }

        if (CryptoClass && !jwk.alg) {
            jwk.alg = CryptoClass.alg2jwk(alg);
        }

        // add key_ops
        if (!("key_ops" in jwk)) {
            jwk.key_ops = keyUsages;
        }
    }
}

function FixImportJwk(jwk: any) {
    if (BrowserInfo().name === Browser.IE) {
        // ext
        if ("ext" in jwk) {
            jwk.extractable = jwk.ext;
            delete jwk.ext;
        }
        delete jwk.key_ops;
        delete jwk.alg;
    }
}

function CheckAppleRsaOAEP(algName: string) {
    const version = /AppleWebKit\/(\d+)/.exec(self.navigator.userAgent);
    return (
        algName.toUpperCase() === AlgorithmNames.RsaOAEP && version && parseInt(version[1], 10) < 604
    );
}
