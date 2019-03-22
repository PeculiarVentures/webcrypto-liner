import * as core from "webcrypto-core";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaOaepProvider extends core.RsaOaepProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    RsaCrypto.checkLib();

    return this.cipher(algorithm, key, data, true);
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    RsaCrypto.checkLib();

    return this.cipher(algorithm, key, data, false);
  }

  private cipher(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer, encrypt: boolean) {
    const fn = this.getOperation(key.algorithm, encrypt);
    let label: ArrayBuffer;
    if (algorithm.label) {
      label = core.BufferSourceConverter.toArrayBuffer(algorithm.label);
    }
    return fn(data, key.data, label).slice(0).buffer;
  }

  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, encrypt: true): typeof asmCrypto.RSA_OAEP_SHA1.encrypt;
  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, encrypt: false): typeof asmCrypto.RSA_OAEP_SHA1.decrypt;
  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, encrypt: boolean): typeof asmCrypto.RSA_OAEP_SHA1.encrypt | typeof asmCrypto.RSA_OAEP_SHA1.decrypt;
  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, encrypt: boolean) {
    const action = encrypt ? "encrypt" : "decrypt";
    switch (keyAlgorithm.hash.name) {
      case "SHA-1":
        return asmCrypto.RSA_OAEP_SHA1[action];
      case "SHA-256":
        return asmCrypto.RSA_OAEP_SHA256[action];
      case "SHA-512":
        return asmCrypto.RSA_OAEP_SHA512[action];
      default:
        throw new core.AlgorithmError("keyAlgorithm.hash: Is not recognized");
    }
  }

}
