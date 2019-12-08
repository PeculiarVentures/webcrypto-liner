import * as core from "webcrypto-core";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesKwProvider extends core.AesKwProvider {
  public async onEncrypt(algorithm: AesCtrParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public async onDecrypt(algorithm: AesCtrParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }
  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }
}
