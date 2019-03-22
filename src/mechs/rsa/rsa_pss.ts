import * as core from "webcrypto-core";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaPssProvider extends core.RsaPssProvider {

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return RsaCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return RsaCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onSign(algorithm: RsaPssParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    RsaCrypto.checkLib();

    const fn = this.getOperation(key.algorithm, true);
    return fn(data, key.data, algorithm.saltLength).buffer;
  }

  public async onVerify(algorithm: RsaPssParams, key: RsaCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    RsaCrypto.checkLib();

    const fn = this.getOperation(key.algorithm, false);
    return fn(signature, data, key.data, algorithm.saltLength);
  }

  public async checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(key);
  }

  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, sign: true): typeof asmCrypto.RSA_PSS_SHA1.sign;
  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, sign: false): typeof asmCrypto.RSA_PSS_SHA1.verify;
  private getOperation(keyAlgorithm: RsaHashedKeyAlgorithm, sign: boolean) {
    const action = sign ? "sign" : "verify";
    switch (keyAlgorithm.hash.name) {
      case "SHA-1":
        return asmCrypto.RSA_PSS_SHA1[action];
      case "SHA-256":
        return asmCrypto.RSA_PSS_SHA256[action];
      case "SHA-512":
        return asmCrypto.RSA_PSS_SHA512[action];
      default:
        throw new core.AlgorithmError("keyAlgorithm.hash: Is not recognized");
    }
  }

}
