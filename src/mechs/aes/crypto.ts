/// <reference path="../../typings/asmcrypto.d.ts" />

import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { nativeCrypto } from "../../native";
import { isAlgorithm } from "../../utils";
import { AesCryptoKey } from "./key";

export class AesCrypto {

  public static AesCBC = "AES-CBC";
  public static AesECB = "AES-ECB";
  public static AesGCM = "AES-GCM";

  public static checkLib() {
    if (typeof(asmCrypto) === "undefined") {
      throw new core.OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/asmcrypto.js' script to your project");
    }
  }

  public static checkCryptoKey(key: any) {
    if (!(key instanceof AesCryptoKey)) {
      throw new TypeError("key: Is not AesCryptoKey");
    }
  }

  public static async generateKey(algorithm: AesKeyGenParams, extractable: boolean, usages: KeyUsage[]) {
    this.checkLib();

    // gat random bytes for key
    const raw = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));

    return new AesCryptoKey(algorithm, extractable, usages, raw);
  }

  public static async encrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer) {
    return this.cipher(algorithm, key, data, true);
  }

  public static async decrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer) {
    return this.cipher(algorithm, key, data, false);
  }

  public static async exportKey(format: string, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    this.checkLib();

    switch (format) {
      case "jwk":
        return key.toJSON();
      case "raw":
        return key.raw.buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(format: string, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    this.checkLib();

    let raw: ArrayBuffer;

    if (core.isJWK(keyData)) {
      raw = Convert.FromBase64Url(keyData.k);
    } else {
      raw = core.BufferSourceConverter.toArrayBuffer(keyData);
    }

    // check key length
    switch (raw.byteLength << 3) {
      case 128:
      case 192:
      case 256:
        break;
      default:
        throw new core.OperationError("keyData: Is wrong key length");
    }

    const key = new AesCryptoKey({ name: algorithm.name, length: raw.byteLength << 3 }, extractable, keyUsages, new Uint8Array(raw));
    return key;
  }

  private static async cipher(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer, encrypt: boolean) {
    this.checkLib();

    const action = encrypt ? "encrypt" : "decrypt";
    let res: Uint8Array;
    if (isAlgorithm<AesCbcParams>(algorithm, AesCrypto.AesCBC)) {
      // AES-CBC
      const iv = core.BufferSourceConverter.toArrayBuffer(algorithm.iv);
      res = asmCrypto.AES_CBC[action](data, key.raw, undefined, iv);
    } else if (isAlgorithm<AesGcmParams>(algorithm, AesCrypto.AesGCM)) {
      // AES-GCM
      const iv = core.BufferSourceConverter.toArrayBuffer(algorithm.iv);
      let additionalData;
      if (algorithm.additionalData) {
        additionalData = core.BufferSourceConverter.toArrayBuffer(algorithm.additionalData);
      }
      const tagLength = (algorithm.tagLength || 128) / 8;
      res = asmCrypto.AES_GCM[action](data, key.raw, iv, additionalData, tagLength);
    } else if (isAlgorithm<Algorithm>(algorithm, AesCrypto.AesECB)) {
      //   // AES-ECB
      res = asmCrypto.AES_ECB[action](data, key.raw, true);
    } else {
      throw new core.OperationError(`algorithm: Is not recognized`);
    }

    return res.buffer;
  }

}
