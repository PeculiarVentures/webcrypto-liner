import * as core from "webcrypto-core";
import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesKwProvider extends core.AesKwProvider {
  public async onEncrypt(_algorithm: AesCtrParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public async onDecrypt(_algorithm: AesCtrParams, _key: CryptoKey, _data: ArrayBuffer): Promise<ArrayBuffer> {
    throw new Error("Method not implemented.");
  }
  public async onGenerateKey(_algorithm: AesKeyGenParams, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }
  public async onExportKey(_format: KeyFormat, _key: CryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    throw new Error("Method not implemented.");
  }
  public async onImportKey(_format: KeyFormat, _keyData: ArrayBuffer | JsonWebKey, _algorithm: Algorithm, _extractable: boolean, _keyUsages: KeyUsage[]): Promise<CryptoKey> {
    throw new Error("Method not implemented.");
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is AesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    AesCrypto.checkCryptoKey(key);
  }
}
