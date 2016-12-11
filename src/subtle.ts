// Core
import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import * as core from "webcrypto-core";
import { PrepareAlgorithm, PrepareData } from "webcrypto-core";

// Base
import { nativeSubtle } from "./init";
import { LinerError } from "./crypto";
import { CryptoKey, CryptoKeyPair } from "./key";
import { string2buffer, buffer2string, concat, Browser, BrowserInfo, assign } from "./helper";

// Crypto
import { AesCrypto } from "./aes/crypto";
import { ShaCrypto } from "./sha/crypto";
import { RsaCrypto } from "./rsa/crypto";
import { EcCrypto } from "./ec/crypto";

declare type IE = any;

const keys: { key: CryptoKey, hash: Algorithm }[] = [];

function PrepareKey(key: CryptoKey, subtle: typeof BaseCrypto): PromiseLike<CryptoKey> {
    let promise = Promise.resolve(key);
    if (!key.key)
        if (!key.extractable) {
            throw new LinerError("'key' is Native CryptoKey. It can't be converted to JS CryptoKey");
        }
        else {
            promise = promise.then(() =>
                self.crypto.subtle.exportKey("jwk", key)
            )
                .then((jwk: any) =>
                    subtle.importKey("jwk", jwk, key.algorithm as Algorithm, true, key.usages)
                );
        }
    return promise;
}

export class SubtleCrypto extends core.SubtleCrypto {

    generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey | NativeCryptoKeyPair> {
        const args = arguments;
        let _alg: Algorithm;
        return super.generateKey.apply(this, args)
            .then((d: Uint8Array) => {
                _alg = PrepareAlgorithm(algorithm);

                try {
                    return nativeSubtle.generateKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native generateKey for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native generateKey for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((keys: CryptoKey | CryptoKeyPair) => {

                if (keys) {
                    FixCryptoKeyUsages(keys, keyUsages);
                    SetHashAlgorithm(_alg, keys);
                    return new Promise(resolve => resolve(keys));
                }
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "generateKey");
                }
                return Class.generateKey(_alg, extractable, keyUsages);
            });
    }

    digest(algorithm: AlgorithmIdentifier, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let _alg: Algorithm;
        let _data: Uint8Array;
        return super.digest.apply(this, args)
            .then((d: Uint8Array) => {
                _alg = PrepareAlgorithm(algorithm);
                _data = PrepareData(data, "data");

                try {
                    return nativeSubtle.digest.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native digest for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native digest for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((digest: ArrayBuffer) => {
                if (digest) return new Promise(resolve => resolve(digest));
                return ShaCrypto.digest(_alg, _data);
            });
    }

    sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let _alg: Algorithm;
        let _data: Uint8Array;
        return super.sign.apply(this, args)
            .then((d: Uint8Array) => {
                _alg = PrepareAlgorithm(algorithm as string);
                _data = PrepareData(data, "data");

                GetHashAlgorithm(_alg, key);
                try {
                    return nativeSubtle.sign.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native sign for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native sign for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((signature: ArrayBuffer) => {
                if (signature) return new Promise(resolve => resolve(signature));
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "sign");
                }
                return PrepareKey(key, Class)
                    .then(key => Class.sign(_alg, key, _data));
            });
    }

    verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: BufferSource, data: BufferSource): PromiseLike<boolean> {
        const args = arguments;
        let _alg: Algorithm;
        let _signature: Uint8Array;
        let _data: Uint8Array;
        return super.verify.apply(this, args)
            .then((d: boolean) => {
                _alg = PrepareAlgorithm(algorithm as string);
                _signature = PrepareData(signature, "data");
                _data = PrepareData(data, "data");

                GetHashAlgorithm(_alg, key);
                try {
                    return nativeSubtle.verify.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native verify for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native verify for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((result: boolean) => {
                if (typeof result === "boolean") return new Promise(resolve => resolve(result));
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "sign");
                }
                return PrepareKey(key, Class)
                    .then(key => Class.verify(_alg, key, _signature, _data));
            });
    }

    deriveBits(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let _alg: Algorithm;
        return super.deriveBits.apply(this, args)
            .then((bits: ArrayBuffer) => {
                _alg = PrepareAlgorithm(algorithm);

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
                        Class = EcCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "deriveBits");
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
                _alg = PrepareAlgorithm(algorithm);
                _algDerivedKey = PrepareAlgorithm(derivedKeyType);

                try {
                    return nativeSubtle.deriveKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native deriveKey for ${_alg.name} doesn't work.`, e.message || "");
                        });
                } catch (e) {
                    // Edge doesn't go to catch of Promise
                    console.warn(`WebCrypto: native deriveKey for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((key: CryptoKey) => {
                if (key) {
                    FixCryptoKeyUsages(key, keyUsages);
                    return new Promise(resolve => resolve(key));
                }
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        Class = EcCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "deriveBits");
                }
                return Class.deriveKey(_alg, baseKey, _algDerivedKey, extractable, keyUsages);
            });
    }

    encrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let _alg: Algorithm;
        let _data: Uint8Array;
        return super.encrypt.apply(this, args)
            .then((bits: ArrayBuffer) => {
                _alg = PrepareAlgorithm(algorithm);
                _data = PrepareData(data, "data");

                try {
                    return nativeSubtle.encrypt.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native 'encrypt' for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native 'encrypt' for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((msg: any) => {
                if (msg) {
                    if (BrowserInfo().name === Browser.IE &&
                        _alg.name.toUpperCase() === AlgorithmNames.AesGCM &&
                        msg.ciphertext) {
                        // Concatinate values in IE
                        let buf = new Uint8Array(msg.ciphertext.byteLength + msg.tag.byteLength);
                        let count = 0;
                        new Uint8Array(msg.ciphertext).forEach((v: number) => buf[count++] = v);
                        new Uint8Array(msg.tag).forEach((v: number) => buf[count++] = v);
                        msg = buf.buffer;
                    }
                    return Promise.resolve(msg);
                }
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                    .then(key => Class.encrypt(_alg, key, _data));
            });
    }
    decrypt(algorithm: AlgorithmIdentifier, key: CryptoKey, data: BufferSource): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let _alg: Algorithm;
        let _data: Uint8Array;
        return super.decrypt.apply(this, args)
            .then((bits: ArrayBuffer) => {
                _alg = PrepareAlgorithm(algorithm);
                _data = PrepareData(data, "data");

                let _data2: any = _data;
                if (BrowserInfo().name === Browser.IE &&
                    _alg.name.toUpperCase() === AlgorithmNames.AesGCM) {
                    // Split buffer
                    const len = _data.byteLength - ((_alg as any).tagLength / 8);
                    _data2 = {
                        ciphertext: _data.buffer.slice(0, len),
                        tag: _data.buffer.slice(len, _data.byteLength)
                    };
                }

                try {
                    return nativeSubtle.decrypt.call(nativeSubtle, _alg, key, _data2)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native 'decrypt' for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native 'decrypt' for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((msg: ArrayBuffer) => {
                if (msg) return new Promise(resolve => resolve(msg));
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                    .then(key => Class.decrypt(_alg, key, _data));
            });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        const args = arguments;
        let _alg: Algorithm;
        return super.wrapKey.apply(this, args)
            .then((bits: ArrayBuffer) => {
                _alg = PrepareAlgorithm(wrapAlgorithm);

                try {
                    return nativeSubtle.wrapKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native 'wrapKey' for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native 'wrapKey' for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((msg: ArrayBuffer) => {
                if (msg) return new Promise(resolve => resolve(msg));
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                return Class.wrapKey(format, key, wrappingKey, _alg);
            });
    }

    unwrapKey(format: string, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        const args = arguments;
        let _alg: Algorithm;
        let _algKey: Algorithm;
        let _data: Uint8Array;
        return super.unwrapKey.apply(this, args)
            .then((bits: ArrayBuffer) => {
                _alg = PrepareAlgorithm(unwrapAlgorithm);
                _algKey = PrepareAlgorithm(unwrappedKeyAlgorithm);
                _data = PrepareData(wrappedKey, "wrappedKey");

                try {
                    return nativeSubtle.unwrapKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native 'unwrapKey' for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native 'unwrapKey' for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((k: CryptoKey) => {
                if (k) {
                    FixCryptoKeyUsages(k, keyUsages);
                    return new Promise(resolve => resolve(k));
                }
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                return Class.unwrapKey(format, _data, unwrappingKey, _alg, _algKey, extractable, keyUsages);
            });
    }

    exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        const args = arguments;
        return super.exportKey.apply(this, args)
            .then(() => {

                try {
                    return nativeSubtle.exportKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native 'exportKey' for ${key.algorithm.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native 'exportKey' for ${key.algorithm.name} doesn't work.`, e.message || "");
                }
            })
            .then((msg: any) => {
                if (msg) {
                    if (format === "jwk" && msg instanceof ArrayBuffer) {
                        msg = buffer2string(new Uint8Array(msg));
                        msg = JSON.parse(msg);
                    }
                    return Promise.resolve(msg);
                }
                if (!key.key)
                    throw new LinerError("Cannot export native CryptoKey from JS implementation");
                let Class: typeof BaseCrypto;
                switch (key.algorithm.name!.toLowerCase()) {
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    case AlgorithmNames.EcDH.toLowerCase():
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "exportKey");
                }
                return Class.exportKey(format, key);
            });
    }

    importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        const args = arguments;
        let _alg: Algorithm;
        let _data: any;
        return super.importKey.apply(this, args)
            .then((bits: ArrayBuffer) => {
                _alg = PrepareAlgorithm(algorithm);
                _data = keyData;

                // Fix: Safari
                if (BrowserInfo().name === Browser.Safari) {
                    // Converts JWK to ArrayBuffer
                    args[1] = string2buffer(JSON.stringify(keyData)).buffer;
                }
                // End: Fix
                if (ArrayBuffer.isView(keyData)) {
                    _data = PrepareData(keyData, "keyData");
                }

                try {
                    return nativeSubtle.importKey.apply(nativeSubtle, args)
                        .catch((e: Error) => {
                            console.warn(`WebCrypto: native 'importKey' for ${_alg.name} doesn't work.`, e.message || "");
                        });
                }
                catch (e) {
                    console.warn(`WebCrypto: native 'importKey' for ${_alg.name} doesn't work.`, e.message || "");
                }
            })
            .then((k: CryptoKey) => {
                if (k) {
                    SetHashAlgorithm(_alg, k);
                    FixCryptoKeyUsages(k, keyUsages);
                    return Promise.resolve(k);
                }
                let Class: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    case AlgorithmNames.EcDH.toLowerCase():
                    case AlgorithmNames.EcDSA.toLowerCase():
                        Class = EcCrypto;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = RsaCrypto;
                        break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "importKey");
                }
                return Class.importKey(format, _data, _alg, extractable, keyUsages);
            });
    }
}

// save hash alg for RSA keys
function SetHashAlgorithm(alg: Algorithm, key: CryptoKey | CryptoKeyPair) {
    if ((BrowserInfo().name === Browser.Edge || BrowserInfo().name === Browser.Safari) && /^rsa/i.test(alg.name)) {
        if ((key as CryptoKeyPair).privateKey) {
            keys.push({ hash: (alg as any).hash, key: (key as CryptoKeyPair).privateKey });
            keys.push({ hash: (alg as any).hash, key: (key as CryptoKeyPair).publicKey });
        }
        else
            keys.push({ hash: (alg as any).hash, key: key as CryptoKey });
    }
}

// fix hash alg for rsa key
function GetHashAlgorithm(alg: Algorithm, key: CryptoKey) {
    if ((BrowserInfo().name === Browser.Edge || BrowserInfo().name === Browser.Safari) && /^rsa/i.test(alg.name)) {
        keys.some(item => {
            if (item.key === key) {
                (alg as any).hash = item.hash;
                return true;
            }
            return false;
        });
    }
}

// Extend Uint8Array for IE
if (!Uint8Array.prototype.forEach) {
    (Uint8Array as any).prototype.forEach = function (cb: (value: number, index: number, array: Uint8Array) => void) {
        for (let i = 0; i < this.length; i++) {
            cb(this[i], i, this);
        }
    };
}
if (!Uint8Array.prototype.slice) {
    (Uint8Array as any).prototype.slice = function (start: number, end: number) {
        return new Uint8Array(this.buffer.slice(start, end));
    };
}
if (!Uint8Array.prototype.filter) {
    (Uint8Array as any).prototype.filter = function (cb: (value: number, index: number, array: Uint8Array) => void) {
        let buf: number[] = [];
        for (let i = 0; i < this.length; i++) {
            if (cb(this[i], i, this))
                buf.push(this[i]);
        }
        return new Uint8Array(buf);
    };
}

function FixCryptoKeyUsages(key: CryptoKey | CryptoKeyPair, keyUsages: string[]) {
    const keys: CryptoKey[] = [];
    if ((key as CryptoKeyPair).privateKey) {
        keys.push((key as CryptoKeyPair).privateKey);
        keys.push((key as CryptoKeyPair).publicKey);
    }
    else {
        keys.push(key as CryptoKey);
    }
    keys.forEach((k: any) => {
        if ("keyUsage" in k) {
            k.usages = k.keyUsage || [];
            // add usages
            if (!k.usages.length) {
                ["verify", "encrypt", "wrapKey"]
                    .forEach(usage => {
                        if (keyUsages.indexOf(usage) > -1 && (k.type === "public" || k.type === "secret"))
                            k.usages.push(usage);
                    });
                ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"]
                    .forEach(usage => {
                        if (keyUsages.indexOf(usage) > -1 && (k.type === "private" || k.type === "secret"))
                            k.usages.push(usage);
                    });
            }
        }
    });
}