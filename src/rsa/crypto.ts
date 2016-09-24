namespace webcrypto.liner.rsa {

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

        static generateKey(alg: webcrypto.rsa.RsaKeyGenParams, extractable: boolean, keyUsage: string[]): PromiseLike<CryptoKeyPair> {
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
                        let keyAlg: webcrypto.rsa.RsaHashedKeyGenParams = key.algorithm as any;
                        let _alg: webcrypto.rsa.RsaPssParams = algorithm as any;
                        let sign: typeof asmCrypto.RSA_PSS_SHA1.sign;
                        switch (keyAlg.hash.name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                sign = asmCrypto.RSA_PSS_SHA1.sign;
                                break;
                            case AlgorithmNames.Sha256:
                                sign = asmCrypto.RSA_PSS_SHA256.sign;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                        }
                        resolve(sign(data, key.key, _alg.saltLength / 8).buffer);
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
                        let keyAlg: webcrypto.rsa.RsaHashedKeyGenParams = key.algorithm as any;
                        let _alg: webcrypto.rsa.RsaPssParams = algorithm as any;
                        let verify: typeof asmCrypto.RSA_PSS_SHA1.verify;
                        switch (keyAlg.hash.name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                verify = asmCrypto.RSA_PSS_SHA1.verify;
                                break;
                            case AlgorithmNames.Sha256:
                                verify = asmCrypto.RSA_PSS_SHA256.verify;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                        }
                        resolve(verify(signature, data, key.key, _alg.saltLength / 8));
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
                        let keyAlg: webcrypto.rsa.RsaHashedKeyGenParams = key.algorithm as any;
                        let _alg: webcrypto.rsa.RsaOaepParams = algorithm as any;
                        let encrypt: typeof asmCrypto.RSA_OAEP_SHA1.encrypt;
                        switch (keyAlg.hash.name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                encrypt = asmCrypto.RSA_OAEP_SHA1.encrypt;
                                break;
                            case AlgorithmNames.Sha256:
                                encrypt = asmCrypto.RSA_OAEP_SHA256.encrypt;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
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
                        let keyAlg: webcrypto.rsa.RsaHashedKeyGenParams = key.algorithm as any;
                        let _alg: webcrypto.rsa.RsaOaepParams = algorithm as any;
                        let decrypt: typeof asmCrypto.RSA_OAEP_SHA1.decrypt;
                        switch (keyAlg.hash.name.toUpperCase()) {
                            case AlgorithmNames.Sha1:
                                decrypt = asmCrypto.RSA_OAEP_SHA1.decrypt;
                                break;
                            case AlgorithmNames.Sha256:
                                decrypt = asmCrypto.RSA_OAEP_SHA256.decrypt;
                                break;
                            default:
                                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
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
                window.crypto.subtle.exportKey(format, key)
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
                        return window.crypto.subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
                    })
                    .then(resolve, reject);
            });
        }

        static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                window.crypto.subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey)
                    .then((data: any) => {
                        let _data: any;
                        if (format.toLowerCase() === "jwk")
                            _data = JSON.parse(buffer2string(new Uint8Array(data)));
                        else
                            _data = new Uint8Array(data);
                        return window.crypto.subtle.importKey(format, _data, unwrappedKeyAlgorithm, extractable, keyUsages);
                    })
                    .then(resolve, reject);
            });
        }

        static exportKey(format: string, key: RsaCryptoKey): PromiseLike<webcrypto.aes.AesJWK | ArrayBuffer> {
            return new Promise((resolve, reject) => {
                throw new LinerError(LinerError.NOT_SUPPORTED);
            });
        }

        static importKey(format: string, keyData: webcrypto.aes.AesJWK | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                let raw: Uint8Array;
                if (format.toLowerCase() === "jwk") {
                    const jwk = keyData as webcrypto.aes.AesJWK;
                    raw = Base64Url.decode(jwk.k);
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
}