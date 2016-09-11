namespace webcrypto.liner.ec {

    declare class Elliptic {
        constructor(namedCurve: string);
        genKeyPair(): EllipticKeyPair;
    }

    declare class EllipticKeyPair {

    }

    declare let elliptic: {
        ec: typeof Elliptic;
    };

    // Helper
    function b2a(buffer: ArrayBuffer | ArrayBufferView) {
        let buf = new Uint8Array(buffer as ArrayBuffer);
        let res: number[] = [];
        for (let i = 0; i < buf.length; i++)
            res.push(buf[i]);
        return res;
    }

    export class EcCrypto extends BaseCrypto {
        protected static checkModule() {
            if (typeof elliptic === "undefined")
                throw new ShimError(ShimError.MODULE_NOT_FOUND, "elliptic", "https://github.com/indutny/elliptic");
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
                (window as any).Crypto.subtle.digest(_alg.hash, data)
                    .then((hash: ArrayBuffer) => {
                        const array = b2a(data);
                        const signature = key.key.sign(array);
                        console.log(signature.toDER());
                        resolve(new ArrayBuffer(0));
                    })
                    .catch(reject);
            });
        }

        static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
            return new Promise(resolve => {
                resolve(key.key.verify(data, signature));
            });
        }

        static deriveKey(algorithm: webcrypto.ec.EcdhKeyDeriveParams, baseKey: CryptoKey, derivedKeyType: aes.AesKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
            return new Promise((resolve, reject) => {
                this.deriveBits(algorithm, baseKey, derivedKeyType.length)
                    .then(bits => {
                        // import bits to AES CryptoKey
                        throw new Error("Not finished yet");
                    });
            });
        }

        static deriveBits(algorithm: webcrypto.ec.EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
            return new Promise((resolve, reject) => {
                const shared = baseKey.key.derive((algorithm.public as CryptoKey).key.getPublic());
                const buf = new Uint8Array(shared.toArray().slice(0, length / 8)).buffer;
                resolve(buf);
            });
        }
    }

}