import * as asmCrypto from "asmcrypto.js";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export type RsaPkcs1Params = Algorithm;
export type RsaPkcs1SignParams = core.HashedAlgorithm;

export class RsaEsProvider extends core.ProviderCrypto {

  public name = "RSAES-PKCS1-v1_5";
  public usages = {
    publicKey: ["encrypt", "wrapKey"] as core.KeyUsages,
    privateKey: ["decrypt", "unwrapKey"] as core.KeyUsages,
  };
  public hashAlgorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

  public async onGenerateKey(algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public checkGenerateKeyParams(algorithm: RsaKeyGenParams) {
    // public exponent
    this.checkRequiredProperty(algorithm, "publicExponent");
    if (!(algorithm.publicExponent && algorithm.publicExponent instanceof Uint8Array)) {
      throw new TypeError("publicExponent: Missing or not a Uint8Array");
    }
    const publicExponent = Convert.ToBase64(algorithm.publicExponent);
    if (!(publicExponent === "Aw==" || publicExponent === "AQAB")) {
      throw new TypeError("publicExponent: Must be [3] or [1,0,1]");
    }

    // modulus length
    this.checkRequiredProperty(algorithm, "modulusLength");
    switch (algorithm.modulusLength) {
      case 1024:
      case 2048:
      case 4096:
        break;
      default:
        throw new TypeError("modulusLength: Must be 1024, 2048, or 4096");
    }
  }

  public async onDecrypt(algorithm: RsaPkcs1Params, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // EM = 0x00 || 0x02 || PS || 0x00 || M
    const EM = new asmCrypto.RSA(key.data).decrypt(new asmCrypto.BigNumber(core.BufferSourceConverter.toUint8Array(data))).result;
    const k = key.algorithm.modulusLength >> 3;
    if (data.byteLength !== k) {
      throw new core.CryptoError("Decryption error. Encrypted message size doesn't match to key length");
    }
    // If the first octet of EM does not have hexadecimal value 0x00, if
    // the second octet of EM does not have hexadecimal value 0x02, if
    // there is no octet with hexadecimal value 0x00 to separate PS from
    // M, or if the length of PS is less than 8 octets, output
    // "decryption error" and stop.
    let offset = 0;
    if (EM[offset++] || EM[offset++] !== 2) {
      throw new core.CryptoError("Decryption error");
    }
    do {
      if (EM[offset++] === 0) {
        break;
      }
    } while (offset < EM.length);

    if (offset < 11) {
      throw new core.CryptoError("Decryption error. PS is less than 8 octets.");
    }

    if (offset === EM.length) {
      throw new core.CryptoError("Decryption error. There is no octet with hexadecimal value 0x00 to separate PS from M");
    }

    return EM.buffer.slice(offset);
  }

  public async onEncrypt(algorithm: RsaPkcs1Params, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const k = key.algorithm.modulusLength >> 3;
    if (data.byteLength > k - 11) {
      throw new core.CryptoError("Message too long");
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    const psLen = k - data.byteLength - 3;
    const PS = RsaCrypto.randomNonZeroValues(new Uint8Array(psLen));
    const EM = new Uint8Array(k);
    EM[0] = 0;
    EM[1] = 2;
    EM.set(PS, 2); // PS
    EM[2 + psLen] = 0;
    EM.set(new Uint8Array(data), 3 + psLen);

    const result = new asmCrypto.RSA(key.data).encrypt(new asmCrypto.BigNumber(EM)).result;
    return core.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is RsaCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(key);
  }

  private async prepareSignData(algorithm: RsaPkcs1SignParams, data: ArrayBuffer) {
    const crypto = new Crypto();
    return crypto.subtle.digest(algorithm.hash, data);
  }
}
