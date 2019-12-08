import * as asmCrypto from "asmcrypto.js";
import * as core from "webcrypto-core";
import { ShaCrypto } from "../sha/crypto";
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
    return this.cipher(algorithm, key, data);
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cipher(algorithm, key, data);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is RsaCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    RsaCrypto.checkCryptoKey(key);
  }

  private cipher(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer) {
    const digest = ShaCrypto.getDigest(key.algorithm.hash.name);
    let label: Uint8Array | undefined;
    if (algorithm.label) {
      label = core.BufferSourceConverter.toUint8Array(algorithm.label);
    }
    const cipher = new asmCrypto.RSA_OAEP(key.data, digest, label);
    let res: Uint8Array;
    const u8Data = core.BufferSourceConverter.toUint8Array(data);
    if (key.type === "public") {
      res = cipher.encrypt(u8Data);
    } else {
      res = cipher.decrypt(u8Data);
    }
    return core.BufferSourceConverter.toArrayBuffer(res);
  }

}
