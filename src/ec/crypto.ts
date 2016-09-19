namespace webcrypto.liner.ec {

    declare class Elliptic {
        constructor(namedCurve: string);
        genKeyPair(): EllipticKeyPair;
        keyFromPrivate(hexString: string | number[] | ArrayBuffer): EllipticKeyPair;
        keyFromPublic(hexString: string | number[] | ArrayBuffer, enc?: string): EllipticKeyPair;
    }

    declare class EllipticKeyPair {
        getPrivate(enc: string): any;
        getPublic(enc: string): any;
    }

    declare let elliptic: {
        ec: typeof Elliptic;
    };

    interface EcCryptoKey extends CryptoKey {
        key: EllipticKeyPair;
    }

    // Helper
    function b2a(buffer: ArrayBuffer | ArrayBufferView) {
        let buf = new Uint8Array(buffer as ArrayBuffer);
        let res: number[] = [];
        for (let i = 0; i < buf.length; i++)
            res.push(buf[i]);
        return res;
    }

    function hex2buffer(hexString: string) {
        let res = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i++)
            res[i / 2] = parseInt(hexString.slice(i, ++i), 16);
        return res;
    }

    function buffer2hex(buffer: Uint8Array): string {
        let res = "";
        for (let i = 0; i < buffer.length; i++) {
            const char = buffer[i].toString(16);
            res += char.length % 2 ? char : "0" + char;
        }
        return res;
    }

    export class EcCrypto extends BaseCrypto {
        protected static checkModule() {
            if (typeof elliptic === "undefined")
                throw new LinerError(LinerError.MODULE_NOT_FOUND, "elliptic", "https://github.com/indutny/elliptic");
        }

        static generateKey(alg: Algorithm, extractable: boolean, keyUsage: string[]) {
            return new Promise<CryptoKeyPair>(resolve => {
                this.checkModule();
                const _alg: webcrypto.ec.EcKeyGenParams = alg as any;
                const key = new elliptic.ec(_alg.namedCurve.replace("-", "").toLowerCase()); // converts name to 'p192', ...

                // set key params
                const prvKey = new CryptoKey();
                const pubKey = new CryptoKey();
                prvKey.key = pubKey.key = key.genKeyPair();
                prvKey.algorithm = pubKey.algorithm = _alg;
                prvKey.extractable = pubKey.extractable = extractable;
                prvKey.type = "private";
                pubKey.type = "public";
                if (alg.name === AlgorithmNames.EcDSA) {
                    prvKey.usages = ["sign"];
                    pubKey.usages = ["verify"];
                }
                else if (alg.name === AlgorithmNames.EcDH) {
                    prvKey.usages = pubKey.usages = ["deriveKey", "deriveBits"];
                }
                resolve({
                    privateKey: prvKey,
                    publicKey: pubKey
                });
            });
        }

        static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const _alg: webcrypto.ec.EcdsaParams = algorithm as any;

                // get digest
                crypto.subtle.digest(_alg.hash, data)
                    .then((hash: ArrayBuffer) => {
                        const array = b2a(data);
                        const signature = key.key.sign(array);
                        resolve(new Uint8Array(signature.toDER()).buffer);
                    })
                    .catch(reject);
            });
        }

        static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
            return new Promise(resolve => {
                resolve(key.key.verify(data, signature));
            });
        }

        static deriveKey(algorithm: webcrypto.ec.EcdhKeyDeriveParams, baseKey: CryptoKey, derivedKeyType: webcrypto.aes.AesKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                let promise = (Promise as any).resolve(null);
                if (!baseKey.key) {
                    /**
                     * Chrome doesn't support AES-192.
                     * Convert key to JS implementation if it's possible 
                     */
                    if (!baseKey.extractable) {
                        throw new LinerError("'baseKey' is Native CryptoKey. It can't be converted to JS CryptoKey");
                    }
                    else {
                        promise = promise.then(() =>
                            crypto.subtle.exportKey("jwk", baseKey)
                        )
                            .then((jwk: any) =>
                                this.importKey("jwk", jwk, baseKey.algorithm, true, baseKey.usages)
                            );
                    }
                }

                promise.then((k: EcCryptoKey) => {
                    if (k)
                        baseKey = k;
                    return this.deriveBits(algorithm, baseKey, derivedKeyType.length);
                })
                    .then((bits: ArrayBuffer) => {
                        return crypto.subtle.importKey("raw", new Uint8Array(bits), derivedKeyType, extractable, keyUsages);
                    })
                    .then(resolve, reject);

            });
        }

        static deriveBits(algorithm: webcrypto.ec.EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                let promise = (Promise as any).resolve(null);
                if (!(algorithm.public as EcCryptoKey).key)
                    promise = promise
                        .then(() =>
                            crypto.subtle.exportKey("jwk", algorithm.public))
                        .then((jwk: any) =>
                            this.importKey("jwk", jwk, baseKey.algorithm, true, baseKey.usages)
                        );
                promise.then((k: EcCryptoKey) => {
                    if (k)
                        algorithm.public = k;
                    const shared = baseKey.key.derive((algorithm.public as CryptoKey).key.getPublic());
                    const buf = new Uint8Array(shared.toArray().slice(0, length / 8)).buffer;
                    return (Promise as any).resolve(buf);
                })
                    .then(resolve, reject);
            });
        }

        static exportKey(format: string, key: EcCryptoKey): PromiseLike<webcrypto.aes.AesJWK | ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const ecKey = key.key;
                if (format.toLowerCase() === "jwk") {
                    let hexPub = ecKey.getPublic("hex").slice(2); // ignore first '04'
                    const hexX = hexPub.slice(0, hexPub.length / 2);
                    const hexY = hexPub.slice(hexPub.length / 2, hexPub.length);
                    if (key.type === "public") {
                        // public

                        let jwk: webcrypto.ec.EcJWKPublicKey = {
                            crv: (key.algorithm as webcrypto.ec.EcKeyAlgorithm).namedCurve,
                            ext: key.extractable,
                            x: Base64Url.encode(hex2buffer(hexX)),
                            y: Base64Url.encode(hex2buffer(hexY)),
                            key_ops: key.usages,
                            kty: "EC"
                        };
                        resolve(jwk);
                    }
                    else {
                        // private
                        let jwk: webcrypto.ec.EcJWKPrivateKey = {
                            crv: (key.algorithm as webcrypto.ec.EcKeyAlgorithm).namedCurve,
                            ext: key.extractable,
                            d: Base64Url.encode(hex2buffer(ecKey.getPrivate("hex"))),
                            x: Base64Url.encode(hex2buffer(hexX)),
                            y: Base64Url.encode(hex2buffer(hexY)),
                            key_ops: key.usages,
                            kty: "EC"
                        };
                        resolve(jwk);
                    }
                }
                else {
                    throw new LinerError(`Format '${format}' is not implemented`);
                }
            });
        }

        static importKey(format: string, keyData: webcrypto.ec.EcJWKPrivateKey | webcrypto.ec.EcJWKPublicKey | Uint8Array, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                const key: EcCryptoKey = new CryptoKey();
                key.algorithm = algorithm;
                if (format.toLowerCase() === "jwk") {
                    const ecKey = new elliptic.ec((keyData as webcrypto.ec.EcJWKPrivateKey).crv.replace("-", "").toLowerCase());
                    if ((keyData as webcrypto.ec.EcJWKPrivateKey).d) {
                        // Private key
                        key.key = ecKey.keyFromPrivate(Base64Url.decode((keyData as webcrypto.ec.EcJWKPrivateKey).d));
                        key.type = "private";
                    }
                    else {
                        // Public key
                        key.key = ecKey.keyFromPublic(
                            concat(
                                new Uint8Array([4]),
                                Base64Url.decode((keyData as webcrypto.ec.EcJWKPrivateKey).x),
                                Base64Url.decode((keyData as webcrypto.ec.EcJWKPrivateKey).y)
                            ));
                        key.type = "public";
                    }
                }
                else
                    throw new LinerError(`Format '${format}' is not implemented`);
                key.extractable = extractable;
                key.usages = keyUsages;
                resolve(key);
            });
        }
    }

}