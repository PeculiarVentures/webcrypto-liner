import * as asmCrypto from "asmcrypto.js";
import * as core from "webcrypto-core";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCtrProvider extends core.AesCtrProvider {

  public async onEncrypt(algorithm: AesCtrParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const result = new asmCrypto.AES_CTR(key.raw, core.BufferSourceConverter.toUint8Array(algorithm.counter))
      .encrypt(core.BufferSourceConverter.toUint8Array(data));
    return core.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onDecrypt(algorithm: AesCtrParams, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const result = new asmCrypto.AES_CTR(key.raw, core.BufferSourceConverter.toUint8Array(algorithm.counter))
      .decrypt(core.BufferSourceConverter.toUint8Array(data));
    return core.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return AesCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    return AesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return AesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }
}
