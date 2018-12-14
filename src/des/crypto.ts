import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url, PrepareData, DesKeyGenParams, DesEdeCbcParams, DesCbcParams } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";
import { nativeCrypto } from "../init";
import { Crypto } from "../crypto";
import * as des from "des.js";

export class DesCrypto extends BaseCrypto {

  public static generateKey(algorithm: DesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): PromiseLike<CryptoKey | CryptoKeyPair> {
    return Promise.resolve()
      .then(() => {
        // gat random bytes for key
        const key = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length >> 3));

        // set key params
        const aesKey = new CryptoKey({
          type: "secret",
          algorithm,
          extractable,
          usages: keyUsages,
        });
        aesKey.key = key as Uint8Array;
        return aesKey;
      });
  }

  public static async encrypt(algorithm: DesCbcParams | DesEdeCbcParams, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    let DesCipher: des.Cipher;
    const iv = PrepareData(algorithm.iv, "iv");
    switch (algorithm.name.toUpperCase()) {
      case AlgorithmNames.DesCBC.toUpperCase():
        DesCipher = des.CBC.instantiate(des.DES).create({
          key: key.key,
          type: "encrypt",
          iv,
        });
        break;
      case AlgorithmNames.DesEdeCBC.toUpperCase():
        DesCipher = des.CBC.instantiate(des.EDE).create({
          key: key.key,
          type: "encrypt",
          iv,
        });
        break;
      default:
        throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
    }
    const enc = DesCipher.update(data).concat(DesCipher.final());
    return new Uint8Array(enc).buffer;
  }

  public static async decrypt(algorithm: DesCbcParams | DesEdeCbcParams, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    let DesCipher: des.Cipher;
    const iv = PrepareData(algorithm.iv, "iv");
    switch (algorithm.name.toUpperCase()) {
      case AlgorithmNames.DesCBC.toUpperCase():
        DesCipher = des.CBC.instantiate(des.DES).create({
          key: key.key,
          type: "decrypt",
          iv,
        });
        break;
      case AlgorithmNames.DesEdeCBC.toUpperCase():
        DesCipher = des.CBC.instantiate(des.EDE).create({
          key: key.key,
          type: "decrypt",
          iv,
        });
        break;
      default:
        throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
    }
    const enc = DesCipher.update(data).concat(DesCipher.final());
    return new Uint8Array(enc).buffer;
  }

  public static async wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: DesCbcParams | DesEdeCbcParams): Promise<ArrayBuffer> {
    const crypto = new Crypto();

    const data = await crypto.subtle.exportKey(format, key);

    let raw: Uint8Array;
    if (!(data instanceof ArrayBuffer)) {
      // JWK
      raw = string2buffer(JSON.stringify(data));
    } else {
      // ArrayBuffer
      raw = new Uint8Array(data);
    }
    return this.encrypt(wrapAlgorithm, wrappingKey, raw);
  }

  public static async unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: DesCbcParams | DesEdeCbcParams, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const crypto = new Crypto();
    const copyKey = unwrappingKey.copy(["decrypt"]);
    const data = await crypto.subtle.decrypt(unwrapAlgorithm, copyKey, wrappedKey);

    let dataAny: any;
    if (format.toLowerCase() === "jwk") {
      dataAny = JSON.parse(buffer2string(new Uint8Array(data)));
    } else {
      dataAny = new Uint8Array(data);
    }
    return this.importKey(format, dataAny, unwrappedKeyAlgorithm, extractable, keyUsages);
  }

  public static alg2jwk(alg: Algorithm): string {
    return `D${(alg as AesKeyAlgorithm).length}${/-(\w+)/i.exec(alg.name!.toUpperCase())![1]}`;
  }

  public static jwk2alg(alg: string): Algorithm {
    throw new Error("Not implemented");
  }

  public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
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

}
