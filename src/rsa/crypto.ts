import { AlgorithmError, AlgorithmNames, Base64Url, BaseCrypto, PrepareData } from "webcrypto-core";
import { LinerError } from "../error";
import { buffer2string, concat, string2buffer } from "../helper";
import { CryptoKey, CryptoKeyPair } from "../key";
import { Crypto } from "../crypto";

interface RsaCryptoKey extends CryptoKey {
    key: asmCrypto.RsaKey;
}

function removeLeadingZero(buf: Uint8Array) {
    let first = true;
    return buf.filter((v) => {
        if (first && v === 0) {
            return false;
        } else {
            first = false;
            return true;
        }
    });
}

export class RsaCrypto extends BaseCrypto {

    public static generateKey(algorithm: RsaKeyGenParams, extractable: boolean, keyUsage: KeyUsage[]): PromiseLike<CryptoKeyPair> {
        return Promise.resolve()
            .then(() => {
                this.checkModule();

                const pubExp = algorithm.publicExponent[0] === 3 ? 3 : 65537;
                const rsaKey = asmCrypto.RSA.generateKey(algorithm.modulusLength, pubExp);
                const privateKey: RsaCryptoKey = new CryptoKey({
                    type: "private",
                    algorithm,
                    extractable,
                    usages: [],
                });
                const publicKey: RsaCryptoKey = new CryptoKey({
                    type: "public",
                    algorithm,
                    extractable: true,
                    usages: [],
                });
                privateKey.key = publicKey.key = rsaKey;
                switch (algorithm.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        privateKey.usages = this.filterUsages(["decrypt", "unwrapKey"], keyUsage);
                        publicKey.usages = this.filterUsages(["encrypt", "wrapKey"], keyUsage);
                        break;
                    case AlgorithmNames.RsaSSA.toLowerCase():
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        privateKey.usages = this.filterUsages(["sign"], keyUsage);
                        publicKey.usages = this.filterUsages(["verify"], keyUsage);
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
                return { privateKey, publicKey };
            });
    }

    public static sign(algorithm: Algorithm, key: RsaCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                switch (algorithm.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase(): {
                        const keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                        const rsaAlg: RsaPssParams = algorithm as any;
                        let sign: typeof asmCrypto.RSA_PKCS1_v1_5_SHA1.sign;
                        switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                sign = asmCrypto.RSA_PKCS1_v1_5_SHA1.sign;
                                break;
                            case AlgorithmNames.Sha256:
                                sign = asmCrypto.RSA_PKCS1_v1_5_SHA256.sign;
                                break;
                            case AlgorithmNames.Sha512:
                                sign = asmCrypto.RSA_PKCS1_v1_5_SHA512.sign;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                        }
                        return sign(data, key.key).buffer;
                    }
                    case AlgorithmNames.RsaPSS.toLowerCase(): {
                        const keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                        const rsaAlg: RsaPssParams = algorithm as any;
                        let sign: typeof asmCrypto.RSA_PSS_SHA1.sign;
                        switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                sign = asmCrypto.RSA_PSS_SHA1.sign;
                                break;
                            case AlgorithmNames.Sha256:
                                sign = asmCrypto.RSA_PSS_SHA256.sign;
                                break;
                            case AlgorithmNames.Sha512:
                                sign = asmCrypto.RSA_PSS_SHA512.sign;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                        }
                        return sign(data, key.key, rsaAlg.saltLength).buffer;
                    }
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
            });
    }

    public static verify(algorithm: Algorithm, key: RsaCryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return Promise.resolve()
            .then(() => {
                switch (algorithm.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase(): {
                        const keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                        const rsaAlg: RsaPssParams = algorithm as any;
                        let verify: typeof asmCrypto.RSA_PKCS1_v1_5_SHA1.verify;
                        switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                verify = asmCrypto.RSA_PKCS1_v1_5_SHA1.verify;
                                break;
                            case AlgorithmNames.Sha256:
                                verify = asmCrypto.RSA_PKCS1_v1_5_SHA256.verify;
                                break;
                            case AlgorithmNames.Sha512:
                                verify = asmCrypto.RSA_PKCS1_v1_5_SHA512.verify;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                        }
                        try {
                            return verify(signature, data, key.key);
                        } catch (err) {
                            console.warn(`Verify error: ${err.message}`);
                            return false;
                        }
                    }
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        const keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                        const rsaAlg: RsaPssParams = algorithm as any;
                        let verify: typeof asmCrypto.RSA_PSS_SHA1.verify;
                        switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                verify = asmCrypto.RSA_PSS_SHA1.verify;
                                break;
                            case AlgorithmNames.Sha256:
                                verify = asmCrypto.RSA_PSS_SHA256.verify;
                                break;
                            case AlgorithmNames.Sha512:
                                verify = asmCrypto.RSA_PSS_SHA512.verify;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                        }
                        try {
                            return verify(signature, data, key.key, rsaAlg.saltLength);
                        } catch (err) {
                            console.warn(`Verify error: ${err.message}`);
                            return false;
                        }
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
            });
    }

    public static encrypt(algorithm: Algorithm, key: RsaCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                switch (algorithm.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        const keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                        const rsaAlg: RsaOaepParams = algorithm as any;
                        let encrypt: typeof asmCrypto.RSA_OAEP_SHA1.encrypt;
                        switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                encrypt = asmCrypto.RSA_OAEP_SHA1.encrypt;
                                break;
                            case AlgorithmNames.Sha256:
                                encrypt = asmCrypto.RSA_OAEP_SHA256.encrypt;
                                break;
                            case AlgorithmNames.Sha512:
                                encrypt = asmCrypto.RSA_OAEP_SHA512.encrypt;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, `${keyAlg.name} ${(keyAlg.hash as Algorithm).name}`);
                        }
                        let label;
                        if (rsaAlg.label) {
                            label = PrepareData(rsaAlg.label, "label");
                        }
                        return encrypt(data, key.key, label);
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
            });
    }

    public static decrypt(algorithm: Algorithm, key: RsaCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                switch (algorithm.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        const keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                        const rsaAlg: RsaOaepParams = algorithm as any;
                        let decrypt: typeof asmCrypto.RSA_OAEP_SHA1.decrypt;
                        switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                decrypt = asmCrypto.RSA_OAEP_SHA1.decrypt;
                                break;
                            case AlgorithmNames.Sha256:
                                decrypt = asmCrypto.RSA_OAEP_SHA256.decrypt;
                                break;
                            case AlgorithmNames.Sha512:
                                decrypt = asmCrypto.RSA_OAEP_SHA512.decrypt;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, `${keyAlg.name} ${(keyAlg.hash as Algorithm).name}`);
                        }
                        let label;
                        if (rsaAlg.label) {
                            label = PrepareData(rsaAlg.label, "label");
                        }
                        return decrypt(data, key.key, label);
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
                }
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
                let preparedData: any;
                if (format.toLowerCase() === "jwk") {
                    preparedData = JSON.parse(buffer2string(new Uint8Array(data)));
                } else {
                    preparedData = new Uint8Array(data);
                }
                return crypto.subtle.importKey(format, preparedData, unwrappedKeyAlgorithm, extractable, keyUsages);
            });
    }

    public static alg2jwk(alg: Algorithm) {
        const hash = (alg as any).hash as Algorithm;
        const hashSize = /(\d+)/.exec(hash.name)![1];
        switch (alg.name!.toUpperCase()) {
            case AlgorithmNames.RsaOAEP.toUpperCase():
                return `RSA-OAEP${hashSize === "1" ? "" : `-${hashSize}`}`;
            case AlgorithmNames.RsaPSS.toUpperCase():
                return `PS${hashSize}`;
            case AlgorithmNames.RsaSSA.toUpperCase():
                return `RS${hashSize}`;
            default:
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
        }
    }

    public static jwk2alg(alg: string): Algorithm {
        throw new Error("Not implemented");
    }

    public static exportKey(format: string, key: RsaCryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                if (format.toLowerCase() === "jwk") {
                    const jwk: JsonWebKey = {
                        kty: "RSA",
                        ext: true,
                        key_ops: key.usages,
                    };
                    jwk.alg = this.alg2jwk(key.algorithm as Algorithm);
                    jwk.n = Base64Url.encode(removeLeadingZero(key.key[0]));
                    jwk.e = Base64Url.encode(removeLeadingZero(key.key[1]));
                    if (key.type === "private") {
                        jwk.d = Base64Url.encode(removeLeadingZero(key.key[2]));
                        jwk.p = Base64Url.encode(removeLeadingZero(key.key[3]));
                        jwk.q = Base64Url.encode(removeLeadingZero(key.key[4]));
                        jwk.dp = Base64Url.encode(removeLeadingZero(key.key[5]));
                        jwk.dq = Base64Url.encode(removeLeadingZero(key.key[6]));
                        jwk.qi = Base64Url.encode(removeLeadingZero(key.key[7]));
                    }
                    return jwk;
                } else {
                    throw new LinerError(LinerError.NOT_SUPPORTED);
                }
            });
    }

    public static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                let jwk: JsonWebKey;
                const key = new CryptoKey({
                    algorithm,
                    extractable,
                    usages,
                });
                key.key = [];
                if (format.toLowerCase() === "jwk") {
                    jwk = keyData as JsonWebKey;
                    key.key[0] = Base64Url.decode(jwk.n!);
                    key.key[1] = Base64Url.decode(jwk.e!)[0] === 3 ? new Uint8Array([0, 0, 0, 3]) : new Uint8Array([0, 1, 0, 1]);
                    if (jwk.d) {
                        key.type = "private";
                        key.key[2] = Base64Url.decode(jwk.d!);
                        key.key[3] = Base64Url.decode(jwk.p!);
                        key.key[4] = Base64Url.decode(jwk.q!);
                        key.key[5] = Base64Url.decode(jwk.dp!);
                        key.key[6] = Base64Url.decode(jwk.dq!);
                        key.key[7] = Base64Url.decode(jwk.qi!);
                    } else {
                        key.type = "public";
                    }
                    return key;
                } else {
                    throw new LinerError(LinerError.NOT_SUPPORTED);
                }
            });
    }

    protected static checkModule() {
        if (typeof asmCrypto === "undefined") {
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    }

    protected static filterUsages(supported: KeyUsage[], given: KeyUsage[]): KeyUsage[] {
        return supported.filter((item1) => !!given.filter((item2) => item1 === item2).length);
    }
}
