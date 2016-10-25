import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import { LinerError } from "../crypto";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";
// import * as asmCrypto from "asmcrypto.js";

interface RsaCryptoKey extends CryptoKey {
    key: asmCrypto.RsaKey;
}

export class RsaCrypto extends BaseCrypto {
    protected static checkModule() {
        if (typeof asmCrypto === "undefined")
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
    }

    static filterUsages(supported: string[], given: string[]): string[] {
        return supported.filter(item1 => !!given.filter(item2 => item1 === item2).length);
    }

    static generateKey(alg: RsaKeyGenParams, extractable: boolean, keyUsage: string[]): PromiseLike<CryptoKeyPair> {
        return new Promise<CryptoKeyPair>(resolve => {
            this.checkModule();

            const pubExp = alg.publicExponent[0] === 3 ? 3 : 65537;
            const rsaKey = asmCrypto.RSA.generateKey(alg.modulusLength, pubExp);
            const privateKey: RsaCryptoKey = new CryptoKey();
            const publicKey: RsaCryptoKey = new CryptoKey();
            privateKey.key = publicKey.key = rsaKey;
            privateKey.algorithm = publicKey.algorithm = alg;
            privateKey.extractable = publicKey.extractable = extractable;
            privateKey.type = "private";
            publicKey.type = "public";
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    privateKey.usages = this.filterUsages(["decrypt", "unwrapKey"], keyUsage);
                    publicKey.usages = this.filterUsages(["encrypt", "wrapKey"], keyUsage);
                    break;
                case AlgorithmNames.RsaPSS.toLowerCase():
                    privateKey.usages = this.filterUsages(["sign"], keyUsage);
                    publicKey.usages = this.filterUsages(["verify"], keyUsage);
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            resolve({ privateKey, publicKey });
        });
    }

    static sign(algorithm: Algorithm, key: RsaCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {

            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaPSS.toLowerCase():
                    let keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                    let _alg: RsaPssParams = algorithm as any;
                    let sign: typeof asmCrypto.RSA_PSS_SHA1.sign;
                    switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            sign = asmCrypto.RSA_PSS_SHA1.sign;
                            break;
                        case AlgorithmNames.Sha256:
                            sign = asmCrypto.RSA_PSS_SHA256.sign;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    resolve(sign(data, key.key, _alg.saltLength).buffer);
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    }

    static verify(algorithm: Algorithm, key: RsaCryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {

            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaPSS.toLowerCase():
                    let keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                    let _alg: RsaPssParams = algorithm as any;
                    let verify: typeof asmCrypto.RSA_PSS_SHA1.verify;
                    switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            verify = asmCrypto.RSA_PSS_SHA1.verify;
                            break;
                        case AlgorithmNames.Sha256:
                            verify = asmCrypto.RSA_PSS_SHA256.verify;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    resolve(verify(signature, data, key.key, _alg.saltLength));
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    }

    static encrypt(algorithm: Algorithm, key: RsaCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {

            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    let keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                    let _alg: RsaOaepParams = algorithm as any;
                    let encrypt: typeof asmCrypto.RSA_OAEP_SHA1.encrypt;
                    switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            encrypt = asmCrypto.RSA_OAEP_SHA1.encrypt;
                            break;
                        case AlgorithmNames.Sha256:
                            encrypt = asmCrypto.RSA_OAEP_SHA256.encrypt;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, `${keyAlg.name} ${(keyAlg.hash as Algorithm).name}`);
                    }
                    resolve(encrypt(data, key.key, _alg.label));
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    }

    static decrypt(algorithm: Algorithm, key: RsaCryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {

            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    let keyAlg: RsaHashedKeyGenParams = key.algorithm as any;
                    let _alg: RsaOaepParams = algorithm as any;
                    let decrypt: typeof asmCrypto.RSA_OAEP_SHA1.decrypt;
                    switch ((keyAlg.hash as Algorithm).name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            decrypt = asmCrypto.RSA_OAEP_SHA1.decrypt;
                            break;
                        case AlgorithmNames.Sha256:
                            decrypt = asmCrypto.RSA_OAEP_SHA256.decrypt;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, `${keyAlg.name} ${(keyAlg.hash as Algorithm).name}`);
                    }
                    resolve(decrypt(data, key.key, _alg.label));
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
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

    static exportKey(format: string, key: RsaCryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            if (format.toLowerCase() === "jwk") {
                const jwk: JsonWebKey = {
                    kty: "RSA",
                    ext: true,
                    key_ops: key.usages
                };
                const hash = (key.algorithm as RsaHashedKeyAlgorithm).hash as Algorithm;
                const hashSize = /(\d)+/.exec(hash.name) ![1];
                switch (key.algorithm.name!.toUpperCase()) {
                    case AlgorithmNames.RsaOAEP.toUpperCase():
                        jwk.alg = `RSA-OAEP-${hashSize}`;
                        break;
                    case AlgorithmNames.RsaPSS.toUpperCase():
                        jwk.alg = `PS${hashSize}`;
                        break;
                    case AlgorithmNames.RsaSSA.toUpperCase():
                        jwk.alg = `RS${hashSize}`;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                }
                jwk.n = Base64Url.encode(key.key[0]);
                jwk.e = Base64Url.encode(key.key[1][3] === 3 ? new Uint8Array([3]) : new Uint8Array([1, 0, 1]));
                if (key.type === "private") {
                    jwk.d = Base64Url.encode(key.key[2]);
                    jwk.p = Base64Url.encode(key.key[3]);
                    jwk.q = Base64Url.encode(key.key[4]);
                    jwk.dp = Base64Url.encode(key.key[5]);
                    jwk.dq = Base64Url.encode(key.key[6]);
                    jwk.qi = Base64Url.encode(key.key[7]);
                }
                resolve(jwk);
            }
            else {
                throw new LinerError(LinerError.NOT_SUPPORTED);
            }
        });
    }

    static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            let raw: Uint8Array;
            let jwk: JsonWebKey;
            const key = new CryptoKey();
            key.algorithm = algorithm;
            key.usages = keyUsages;
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
                }
                else
                    key.type = "public";
                resolve(key);
            }
            else
                throw new LinerError(LinerError.NOT_SUPPORTED);
            resolve(key);
        });
    }
}