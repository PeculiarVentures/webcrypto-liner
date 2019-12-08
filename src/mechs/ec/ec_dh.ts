import * as core from "webcrypto-core";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdhProvider extends core.EcdhProvider {

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return EcCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return EcCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: EcCryptoKey, length: number): Promise<ArrayBuffer> {
    EcCrypto.checkLib();

    const shared = baseKey.data.derive((algorithm.public as EcCryptoKey).data.getPublic());
    let array = new Uint8Array(shared.toArray());

    // Padding
    let len = array.length;
    len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
    if (array.length < len) {
      array = EcCrypto.concat(new Uint8Array(len - array.length), array);
    }
    const buf = array.slice(0, length / 8).buffer;
    return buf;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is EcCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    EcCrypto.checkCryptoKey(key);
  }

}
