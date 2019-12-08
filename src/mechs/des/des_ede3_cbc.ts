import * as core from "webcrypto-core";
import { DesCrypto } from "./crypto";
import { DesCryptoKey } from "./key";

export type DesEde3CbcParams = core.DesParams;

export class DesEde3CbcProvider extends core.DesProvider {

  public keySizeBits = 192;
  public ivSize = 8;
  public name = "DES-EDE3-CBC";

  public async onGenerateKey(algorithm: core.DesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return DesCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: DesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return DesCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: core.DesImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return DesCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: core.DesParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.encrypt(algorithm, key, data);
  }

  public async onDecrypt(algorithm: core.DesParams, key: DesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return DesCrypto.decrypt(algorithm, key, data);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is DesCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    DesCrypto.checkCryptoKey(key);
  }

}
