import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import { LinerError } from "../crypto";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";
// import * as elliptic from "elliptic";
declare let elliptic: any;


interface EcCryptoKey extends CryptoKey {
    key: EllipticJS.EllipticKeyPair;
}

// Helper
function b2a(buffer: ArrayBuffer | ArrayBufferView) {
    let buf = new Uint8Array(buffer as ArrayBuffer);
    let res: number[] = [];
    for (let i = 0; i < buf.length; i++)
        res.push(buf[i]);
    return res;
}

function hex2buffer(hexString: string, padded?: boolean) {
    if (hexString.length % 2) {
        hexString = "0" + hexString;
    }
    let res = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i++) {
        const c = hexString.slice(i, ++i + 1);
        res[(i - 1) / 2] = parseInt(c, 16);
    }
    // BN padding
    if (padded) {
        let len = res.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if (res.length < len)
            res = concat(new Uint8Array(len - res.length), res);
    }
    return res;
}

function buffer2hex(buffer: Uint8Array, padded?: boolean): string {
    let res = "";
    for (let i = 0; i < buffer.length; i++) {
        const char = buffer[i].toString(16);
        res += char.length % 2 ? "0" + char : char;
    }

    // BN padding
    if (padded) {
        let len = buffer.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if ((res.length / 2) < len)
            res = new Array(len * 2 - res.length + 1).join("0") + res;
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
            const _alg: EcKeyGenParams = alg as any;
            const key = new elliptic.ec(_alg.namedCurve.replace("-", "").toLowerCase()); // converts name to 'p192', ...

            // set key params
            const prvKey = new CryptoKey();
            const pubKey = new CryptoKey();
            prvKey.key = pubKey.key = key.genKeyPair();
            prvKey.algorithm = pubKey.algorithm = _alg;
            prvKey.extractable = extractable;
            pubKey.extractable = true;
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
            const _alg: EcdsaParams = algorithm as any;

            // get digest
            (self.crypto.subtle.digest(_alg.hash, data) as Promise<ArrayBuffer>)
                .then(hash => {
                    const array = b2a(hash);
                    const signature = key.key.sign(array);
                    const hexSignature = buffer2hex(signature.r.toArray(), true) + buffer2hex(signature.s.toArray(), true);
                    resolve(hex2buffer(hexSignature).buffer);
                })
                .catch(reject);
        });
    }

    static verify(algorithm: Algorithm, key: CryptoKey, signature: Uint8Array, data: Uint8Array): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            const _alg: EcdsaParams = algorithm as any;
            const sig = {
                r: signature.slice(0, signature.byteLength / 2),
                s: signature.slice(signature.byteLength / 2)
            };
            // get digest
            (self.crypto.subtle.digest(_alg.hash, data) as Promise<ArrayBuffer>)
                .then(hash => {
                    const array = b2a(hash);
                    resolve(key.key.verify(array, sig));
                })
                .catch(reject);
        });
    }

    static deriveKey(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, derivedKeyType: AesKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.deriveBits(algorithm, baseKey, derivedKeyType.length)
                .then((bits: ArrayBuffer) => {
                    return self.crypto.subtle.importKey("raw", new Uint8Array(bits), derivedKeyType, extractable, keyUsages);
                })
                .then(resolve, reject);
        });
    }

    static deriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            let promise = (Promise as any).resolve(null);
            const shared = baseKey.key.derive((algorithm.public as CryptoKey).key.getPublic());
            let array = new Uint8Array(shared.toArray());
            // Padding
            let len = array.length;
            len = len > 32 ? len > 48 ? 66 : 48 : 32;
            if (array.length < len)
                array = concat(new Uint8Array(len - array.length), array);
            const buf = array.slice(0, length / 8).buffer;
            resolve(buf);
        });
    }

    static exportKey(format: string, key: EcCryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            const ecKey = key.key;
            if (format.toLowerCase() === "jwk") {
                let hexPub = ecKey.getPublic("hex").slice(2); // ignore first '04'
                const hexX = hexPub.slice(0, hexPub.length / 2);
                const hexY = hexPub.slice(hexPub.length / 2, hexPub.length);
                if (key.type === "public") {
                    // public
                    let jwk: JsonWebKey = {
                        crv: (key.algorithm as EcKeyGenParams).namedCurve,
                        ext: key.extractable,
                        x: Base64Url.encode(hex2buffer(hexX, true)),
                        y: Base64Url.encode(hex2buffer(hexY, true)),
                        key_ops: [],
                        kty: "EC"
                    };
                    resolve(jwk);
                }
                else {
                    // private
                    let jwk: JsonWebKey = {
                        crv: (key.algorithm as EcKeyGenParams).namedCurve,
                        ext: key.extractable,
                        d: Base64Url.encode(hex2buffer(ecKey.getPrivate("hex"), true)),
                        x: Base64Url.encode(hex2buffer(hexX, true)),
                        y: Base64Url.encode(hex2buffer(hexY, true)),
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

    static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            const key: EcCryptoKey = new CryptoKey();
            key.algorithm = algorithm;
            if (format.toLowerCase() === "jwk") {
                const ecKey = new elliptic.ec((keyData as JsonWebKey).crv!.replace("-", "").toLowerCase());
                if ((keyData as JsonWebKey).d) {
                    // Private key
                    key.key = ecKey.keyFromPrivate(Base64Url.decode((keyData as JsonWebKey).d!));
                    key.type = "private";
                }
                else {
                    // Public key
                    let bufferPubKey = concat(
                        new Uint8Array([4]),
                        Base64Url.decode((keyData as JsonWebKey).x!),
                        Base64Url.decode((keyData as JsonWebKey).y!)
                    );
                    const hexPubKey = buffer2hex(bufferPubKey);

                    key.key = ecKey.keyFromPublic(hexPubKey, "hex");
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