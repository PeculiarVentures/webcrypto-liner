import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";
import { nativeCrypto } from "../init";

interface AesCryptoKey extends CryptoKey {
    key: Uint8Array;
}

export class AesCrypto extends BaseCrypto {

    public static generateKey(alg: AesKeyGenParams, extractable: boolean, keyUsage: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
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
                return aesKey;
            });
    }

    public static encrypt(algorithm: Algorithm, key: AesCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                let res: Uint8Array;
                switch (algorithm.name.toUpperCase()) {
                    case AlgorithmNames.AesCBC:
                        const algCBC = algorithm as AesCbcParams;
                        res = asmCrypto.AES_CBC.encrypt(data, key.key, undefined, algCBC.iv) as Uint8Array;
                        break;
                    case AlgorithmNames.AesGCM:
                        const algGCM = algorithm as AesGcmParams;
                        algGCM.tagLength = algGCM.tagLength || 128;
                        res = asmCrypto.AES_GCM.encrypt(data, key.key, algGCM.iv, algGCM.additionalData, algGCM.tagLength / 8) as Uint8Array;
                        break;
                    default:
                        throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
                return res.buffer;
            });
    }

    public static decrypt(algorithm: Algorithm, key: AesCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                let res: Uint8Array;

                switch (algorithm.name.toUpperCase()) {
                    case AlgorithmNames.AesCBC:
                        const algCBC = algorithm as AesCbcParams;
                        res = asmCrypto.AES_CBC.decrypt(data, key.key, undefined, algCBC.iv) as Uint8Array;
                        break;
                    case AlgorithmNames.AesGCM:
                        const algGCM = algorithm as AesGcmParams;
                        algGCM.tagLength = algGCM.tagLength || 128;
                        res = asmCrypto.AES_GCM.decrypt(data, key.key, algGCM.iv, algGCM.additionalData, algGCM.tagLength / 8) as Uint8Array;
                        break;
                    default:
                        throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
                return res.buffer;
            });
    }

    public static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): PromiseLike<ArrayBuffer> {
        let crypto: Crypto;
        return Promise.resolve()
            .then(() => {
                crypto = new Crypto();
                return crypto.subtle.exportKey(format, key);
            })
            .then((data: any) => {
                let raw: Uint8Array;
                if (!(data instanceof ArrayBuffer)) {
                    // JWK
                    raw = string2buffer(JSON.stringify(data));
                } else {
                    // ArrayBuffer
                    raw = new Uint8Array(data);
                }
                return crypto.subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
            });
    }

    public static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        let crypto: Crypto;
        return Promise.resolve()
            .then(() => {
                crypto = new Crypto();
                return crypto.subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
            })
            .then((data: any) => {
                let dataAny: any;
                if (format.toLowerCase() === "jwk") {
                    dataAny = JSON.parse(buffer2string(new Uint8Array(data)));
                } else {
                    dataAny = new Uint8Array(data);
                }
                return crypto.subtle.importKey(format, dataAny, unwrappedKeyAlgorithm, extractable, keyUsages);
            });
    }

    public static alg2jwk(alg: Algorithm): string {
        return `A${(alg as AesKeyAlgorithm).length}${/-(\w+)/i.exec(alg.name!.toUpperCase()) ![1]}`;
    }

    public static jwk2alg(alg: string): Algorithm {
        throw new Error("Not implemented");
    }

    public static exportKey(format: string, key: AesCryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                const raw = key.key;
                if (format.toLowerCase() === "jwk") {
                    const jwk: JsonWebKey = {
                        alg: this.alg2jwk(key.algorithm as Algorithm),
                        ext: key.extractable,
                        k: Base64Url.encode(raw),
                        key_ops: key.usages,
                        kty: "oct",
                    };
                    return jwk;
                } else {
                    return raw.buffer;
                }
            });
    }

    public static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                let raw: Uint8Array;
                if (format.toLowerCase() === "jwk") {
                    const jwk = keyData as JsonWebKey;
                    raw = Base64Url.decode(jwk.k!);
                } else {
                    raw = new Uint8Array(keyData as Uint8Array);
                }
                const key = new CryptoKey();
                key.algorithm = algorithm;
                key.type = "secret";
                key.usages = keyUsages;
                key.key = raw;
                return key;
            });
    }

    protected static checkModule() {
        if (typeof asmCrypto === "undefined") {
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    }

}

import { Crypto } from "../crypto";
