import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import { LinerError } from "../crypto";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";
import * as asmCrypto from "asmcrypto.js";
import { nativeCrypto } from "../init";

interface AesCryptoKey extends CryptoKey {
    key: Uint8Array;
}

export class AesCrypto extends BaseCrypto {
    protected static checkModule() {
        if (typeof asmCrypto === "undefined")
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
    }

    static generateKey(alg: AesKeyGenParams, extractable: boolean, keyUsage: string[]): PromiseLike<CryptoKey> {
        return new Promise<CryptoKey>(resolve => {
            this.checkModule();

            // gat random bytes for key
            const key = nativeCrypto.getRandomValues(new Uint8Array(alg.length / 8));

            // set key params
            const aesKey: AesCryptoKey = new CryptoKey();
            aesKey.key = key as Uint8Array;
            aesKey.algorithm = alg;
            aesKey.extractable = extractable;
            aesKey.type = "secret";
            aesKey.usages = keyUsage;
            resolve(aesKey);
        });
    }

    static encrypt(algorithm: Algorithm, key: AesCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise(resolve => {
            let res: Uint8Array;
            switch (algorithm.name.toUpperCase()) {
                case AlgorithmNames.AesCBC:
                    let algCBC = algorithm as AesCbcParams;
                    res = asmCrypto.AES_CBC.encrypt(data, key.key, undefined, algCBC.iv) as Uint8Array;
                    break;
                case AlgorithmNames.AesGCM:
                    let algGCM = algorithm as AesGcmParams;
                    algGCM.tagLength = algGCM.tagLength || 128;
                    res = asmCrypto.AES_GCM.encrypt(data, key.key, algGCM.iv, algGCM.additionalData, algGCM.tagLength / 8) as Uint8Array;
                    break;
                default:
                    throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            resolve(res.buffer);
        });
    }

    static decrypt(algorithm: Algorithm, key: AesCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise(resolve => {
            let res: Uint8Array;

            switch (algorithm.name.toUpperCase()) {
                case AlgorithmNames.AesCBC:
                    let algCBC = algorithm as AesCbcParams;
                    res = asmCrypto.AES_CBC.decrypt(data, key.key, undefined, algCBC.iv) as Uint8Array;
                    break;
                case AlgorithmNames.AesGCM:
                    let algGCM = algorithm as AesGcmParams;
                    algGCM.tagLength = algGCM.tagLength || 128;
                    res = asmCrypto.AES_GCM.decrypt(data, key.key, algGCM.iv, algGCM.additionalData, algGCM.tagLength / 8) as Uint8Array;
                    break;
                default:
                    throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            resolve(res.buffer);
        });
    }

    static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            self.crypto.subtle.exportKey(format, key)
                .then((data: any) => {
                    let raw: Uint8Array;
                    if (!(data instanceof ArrayBuffer)) {
                        // JWK
                        raw = string2buffer(JSON.stringify(data));
                    }
                    else {
                        // ArrayBuffer
                        raw = new Uint8Array(data);
                    }
                    return self.crypto.subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
                })
                .then(resolve, reject);
        });
    }

    static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            self.crypto.subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey)
                .then((data: any) => {
                    let _data: any;
                    if (format.toLowerCase() === "jwk")
                        _data = JSON.parse(buffer2string(new Uint8Array(data)));
                    else
                        _data = new Uint8Array(data);
                    return self.crypto.subtle.importKey(format, _data, unwrappedKeyAlgorithm, extractable, keyUsages);
                })
                .then(resolve, reject);
        });
    }

    static exportKey(format: string, key: AesCryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const raw = key.key;
            if (format.toLowerCase() === "jwk") {
                let jwk: JsonWebKey = {
                    alg: `A${(key.algorithm as AesKeyAlgorithm).length}${/-(\w+)/i.exec(key.algorithm.name!.toUpperCase()) ![1]}`,
                    ext: key.extractable,
                    k: Base64Url.encode(raw),
                    key_ops: key.usages,
                    kty: "oct"
                };
                resolve(jwk);
            }
            else {
                resolve(raw.buffer);
            }
        });
    }

    static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            let raw: Uint8Array;
            if (format.toLowerCase() === "jwk") {
                const jwk = keyData as JsonWebKey;
                raw = Base64Url.decode(jwk.k!);
            }
            else
                raw = new Uint8Array(keyData as Uint8Array);
            const key = new CryptoKey();
            key.algorithm = algorithm;
            key.type = "secret";
            key.usages = keyUsages;
            key.key = raw;
            resolve(key);
        });
    }
}