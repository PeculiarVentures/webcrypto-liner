import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url, PrepareData } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";
import { nativeCrypto } from "../init";
import { Crypto } from "../crypto";

interface AesCryptoKey extends CryptoKey {
    key: Uint8Array;
}

interface AesEcbParams extends Algorithm {
    padding?: boolean;
}

export class AesCrypto extends BaseCrypto {

    public static generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): PromiseLike<CryptoKey | CryptoKeyPair> {
        return Promise.resolve()
            .then(() => {
                this.checkModule();

                // gat random bytes for key
                const key = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));

                // set key params
                const aesKey: AesCryptoKey = new CryptoKey({
                    type: "secret",
                    algorithm,
                    extractable,
                    usages: keyUsages,
                });
                aesKey.key = key as Uint8Array;
                return aesKey;
            });
    }

    public static encrypt(algorithm: Algorithm, key: AesCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                let res: Uint8Array;
                switch (algorithm.name.toUpperCase()) {
                    case AlgorithmNames.AesECB:
                        const algECB = algorithm as AesEcbParams;
                        res = asmCrypto.AES_ECB.encrypt(data, key.key, !!algECB.padding) as Uint8Array;
                        break;
                    case AlgorithmNames.AesCBC:
                        const algCBC = algorithm as AesCbcParams;
                        res = asmCrypto.AES_CBC.encrypt(data, key.key, undefined, PrepareData(algCBC.iv as Uint8Array, "iv")) as Uint8Array;
                        break;
                    case AlgorithmNames.AesGCM:
                        const algGCM = algorithm as AesGcmParams;
                        algGCM.tagLength = algGCM.tagLength || 128;
                        let additionalData;
                        if (algGCM.additionalData) {
                            additionalData = PrepareData(algGCM.additionalData, "additionalData");
                        }
                        res = asmCrypto.AES_GCM.encrypt(data, key.key, algGCM.iv as Uint8Array, additionalData, algGCM.tagLength / 8) as Uint8Array;
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
                    case AlgorithmNames.AesECB:
                        const algECB = algorithm as AesEcbParams;
                        res = asmCrypto.AES_ECB.decrypt(data, key.key, !!algECB.padding) as Uint8Array;
                        break;
                    case AlgorithmNames.AesCBC:
                        const algCBC = algorithm as AesCbcParams;
                        res = asmCrypto.AES_CBC.decrypt(data, key.key, undefined, PrepareData(algCBC.iv as Uint8Array, "iv")) as Uint8Array;
                        break;
                    case AlgorithmNames.AesGCM:
                        const algGCM = algorithm as AesGcmParams;
                        algGCM.tagLength = algGCM.tagLength || 128;
                        let additionalData;
                        if (algGCM.additionalData) {
                            additionalData = PrepareData(algGCM.additionalData, "additionalData");
                        }
                        res = asmCrypto.AES_GCM.decrypt(data, key.key, algGCM.iv as Uint8Array, additionalData, algGCM.tagLength / 8) as Uint8Array;
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
                const copyKey = wrappingKey.copy(["encrypt"]);
                return crypto.subtle.encrypt(wrapAlgorithm, copyKey, raw);
            });
    }

    public static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        let crypto: Crypto;
        return Promise.resolve()
            .then(() => {
                crypto = new Crypto();
                const copyKey = unwrappingKey.copy(["decrypt"]);
                return crypto.subtle.decrypt(unwrapAlgorithm, copyKey, wrappedKey);
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
        return `A${(alg as AesKeyAlgorithm).length}${/-(\w+)/i.exec(alg.name!.toUpperCase())![1]}`;
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

    public static async importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]): Promise<CryptoKey> {
        let raw: Uint8Array;
        if (format.toLowerCase() === "jwk") {
            const jwk = keyData as JsonWebKey;
            raw = Base64Url.decode(jwk.k!);
        } else {
            raw = new Uint8Array(keyData as Uint8Array);
        }

        const key = new CryptoKey({
            type: "secret",
            algorithm,
            extractable,
            usages,
        });
        key.key = raw;
        return key;
    }

    protected static checkModule() {
        if (typeof asmCrypto === "undefined") {
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    }

}
