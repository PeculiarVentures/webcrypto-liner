/// <reference path="../typings/asmcrypto.d.ts" />

import { BaseCrypto, PrepareData, AlgorithmNames } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";
import { AesCrypto } from "../aes/crypto";
import { DesCrypto } from "../des/crypto";
import { Crypto } from "../crypto";

export class PbkdfCrypto extends BaseCrypto {

  public static async importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]): Promise<CryptoKey> {
    const key = new CryptoKey({
      algorithm,
      extractable,
      type: "secret",
      usages,
    });

    if (format && format.toLowerCase() === "raw") {
      key.key = PrepareData(keyData as BufferSource, "keyData");
    } else {
      throw new LinerError("format: Is not 'raw'");
    }

    return key;
  }

  public static async exportKey(format: string, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    if (format && format.toLowerCase() === "raw") {
      return key.key.buffer;
    } else {
      throw new LinerError("format: Is not 'raw'");
    }

  }

  public static async deriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
    let result: Uint8Array;
    const salt = PrepareData(algorithm.salt, "salt");
    const password = PrepareData(baseKey.key, "key");
    switch ((algorithm.hash as Algorithm).name.toUpperCase()) {
      case "SHA-1":
        result = asmCrypto.PBKDF2_HMAC_SHA1.bytes(password, salt, algorithm.iterations, length >> 3);
        break;
      case "SHA-256":
        result = asmCrypto.PBKDF2_HMAC_SHA256.bytes(password, salt, algorithm.iterations, length >> 3);
        break;
      default:
        throw new LinerError(`algorithm.hash: '${(algorithm.hash as Algorithm).name}' hash algorithm is not supported`);
    }
    return result.buffer;
  }

  public static async deriveKey(algorithm: Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: AesDerivedKeyParams, extractable: boolean, keyUsages: string[]): Promise<CryptoKey> {
    const crypto = new Crypto();

    const bits = await crypto.subtle.deriveBits(algorithm, baseKey, derivedKeyType.length);

    let CryptoClass: typeof BaseCrypto;
    switch (derivedKeyType.name.toLowerCase()) {
      case AlgorithmNames.AesECB.toLowerCase():
      case AlgorithmNames.AesCBC.toLowerCase():
      case AlgorithmNames.AesGCM.toLowerCase():
        CryptoClass = AesCrypto;
        break;
      case AlgorithmNames.DesCBC.toLowerCase():
      case AlgorithmNames.DesEdeCBC.toLowerCase():
        CryptoClass = DesCrypto;
        break;
      default:
        throw new LinerError(`derivedKeyType.name: '${derivedKeyType.name}' algorithm is not supported`);
    }
    const key = await CryptoClass.importKey("raw", bits, derivedKeyType as any, extractable, keyUsages);
    return key as CryptoKey;
  }

  protected static checkModule() {
    if (typeof asmCrypto === "undefined") {
      throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
    }
  }

}
