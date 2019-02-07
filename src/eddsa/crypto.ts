import {
  BaseCrypto,
  AlgorithmNames,
  Base64Url,
} from "webcrypto-core";
import { concat } from "../helper";
import { LinerError } from "../error";
import { CryptoKey } from "../key";
declare const elliptic: any;

interface EddsaCryptoKey extends CryptoKey {
  key: EllipticJS.EllipticKeyPair;
}

// Helper
function b2a(buffer: ArrayBuffer | ArrayBufferView) {
  const buf = new Uint8Array(buffer as ArrayBuffer);
  const res: number[] = [];
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < buf.length; i++) {
    res.push(buf[i]);
  }
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
    len = len > 32 ? (len > 48 ? 66 : 48) : 32;
    if (res.length < len) {
      res = concat(new Uint8Array(len - res.length), res);
    }
  }
  return res;
}

function buffer2hex(buffer: Uint8Array, padded?: boolean): string {
  let res = "";
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < buffer.length; i++) {
    const char = buffer[i].toString(16);
    res += char.length % 2 ? "0" + char : char;
  }

  // BN padding
  if (padded) {
    let len = buffer.length;
    len = len > 32 ? (len > 48 ? 66 : 48) : 32;
    if (res.length / 2 < len) {
      res = new Array(len * 2 - res.length + 1).join("0") + res;
    }
  }

  return res;
}

export class EddsaCrypto extends BaseCrypto {
  public static async sign(
    algorithm: Algorithm,
    key: CryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer> {
    const alg: EcdsaParams = algorithm as any;

    // get digests
    const crypto = new Crypto();
    let array;
    if (algorithm.name.toUpperCase() === AlgorithmNames.EdDSA) {
      array = data;
      return await key.key.sign(array).toBytes();
    } else {
      const hash = await crypto.subtle.digest(alg.hash, data);
      array = b2a(hash);
      const signature = await key.key.sign(array);
      const hexSignature =
        buffer2hex(signature.r.toArray(), true) +
        buffer2hex(signature.s.toArray(), true);
      return hex2buffer(hexSignature).buffer;
    }
  }

  public static async verify(
    algorithm: Algorithm,
    key: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean> {
    const alg: EcdsaParams = algorithm as any;
    let hashedData: ArrayBuffer;
    let sig: { r: Uint8Array; s: Uint8Array } | number[];
    if (algorithm.name.toUpperCase() === AlgorithmNames.EdDSA) {
      sig = b2a(signature);
      hashedData = data.buffer;
    } else {
      sig = {
        r: signature.slice(0, signature.byteLength / 2),
        s: signature.slice(signature.byteLength / 2),
      };
      // get digest
      const crypto = new Crypto();
      hashedData = await crypto.subtle.digest(alg.hash, data);
    }
    const array = b2a(hashedData);
    return key.key.verify(array, sig);
  }

  public static generateKey(
    algorithm: Algorithm,
    extractable: boolean,
    keyUsage: string[],
  ) {
    return Promise.resolve().then(() => {
      this.checkModule();
      const key = new elliptic.ec("ed25519");

      // set key params
      const prvKey = new CryptoKey({
        type: "private",
        algorithm,
        extractable,
        usages: [],
      });
      const pubKey = new CryptoKey({
        type: "public",
        algorithm,
        extractable: true,
        usages: [],
      });
      prvKey.key = pubKey.key = key.genKeyPair();
      if (algorithm.name === AlgorithmNames.EdDSA) {
        prvKey.usages = ["sign"];
        pubKey.usages = ["verify"];
      }
      return {
        privateKey: prvKey,
        publicKey: pubKey,
      };
    });
  }

  public static exportKey(
    format: string,
    key: EddsaCryptoKey,
  ): PromiseLike<JsonWebKey | ArrayBuffer> {
    return Promise.resolve().then(() => {
      const ecKey = key.key;
      if (format.toLowerCase() === "jwk") {
        const hexPub = ecKey.getPublic("hex").slice(2); // ignore first '04'
        const hexX = hexPub.slice(0, hexPub.length / 2);
        const hexY = hexPub.slice(hexPub.length / 2, hexPub.length);
        if (key.type === "public") {
          // public
          const jwk: JsonWebKey = {
            crv: (key.algorithm as EcKeyGenParams).namedCurve,
            ext: key.extractable,
            x: Base64Url.encode(hex2buffer(hexX, true)),
            y: Base64Url.encode(hex2buffer(hexY, true)),
            key_ops: key.usages,
            kty: "EC",
          };
          return jwk;
        } else {
          // private
          const jwk: JsonWebKey = {
            crv: (key.algorithm as EcKeyGenParams).namedCurve,
            ext: key.extractable,
            d: Base64Url.encode(hex2buffer(ecKey.getPrivate("hex"), true)),
            x: Base64Url.encode(hex2buffer(hexX, true)),
            y: Base64Url.encode(hex2buffer(hexY, true)),
            key_ops: key.usages,
            kty: "OKP",
          };
          return jwk;
        }
      } else {
        throw new LinerError(`Format '${format}' is not implemented`);
      }
    });
  }

  public static async importKey(
    format: string,
    keyData: JsonWebKey | BufferSource,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> {
    const key: EddsaCryptoKey = new CryptoKey({
      algorithm,
      extractable,
      usages: keyUsages,
    });
    if (format.toLowerCase() === "jwk") {
      const namedCurve = "ed25519";
      console.log(namedCurve);
      const eddsa = new elliptic.eddsa(namedCurve);

      if ((keyData as JsonWebKey).d) {
        // Private key
        if ((algorithm as EcKeyImportParams).name.toLowerCase() === "eddsa") {
          key.key = eddsa.keyFromSecret(
            Base64Url.decode((keyData as JsonWebKey).d!),
          );
        } else {
          key.key = eddsa.keyFromPrivate(
            Base64Url.decode((keyData as JsonWebKey).d!),
          );
        }
        key.type = "private";
      } else {
        let bufferPubKey;
        bufferPubKey = Base64Url.decode((keyData as JsonWebKey).x!);
        const hexPubKey = buffer2hex(bufferPubKey);

        key.key = eddsa.keyFromPublic(hexPubKey, "hex");
        key.type = "public";
      }
    } else {
      throw new LinerError(`Format '${format}' is not implemented`);
    }
    return key;
  }

  protected static checkModule() {
    if (typeof elliptic === "undefined") {
      throw new LinerError(
        LinerError.MODULE_NOT_FOUND,
        "elliptic",
        "https://github.com/indutny/elliptic",
      );
    }
  }
}
