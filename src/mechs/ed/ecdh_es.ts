import * as core from "webcrypto-core";
import { EdCrypto } from "./crypto";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EcdhEsProvider extends core.EcdhEsProvider {

  public namedCurves: string[] = ["X25519"];

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await EdCrypto.generateKey(
      {
        name: this.name,
        namedCurve: algorithm.namedCurve.replace(/^x/i, "X"),
      },
      extractable,
      keyUsages);

    return keys;
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: EdPrivateKey, length: number): Promise<ArrayBuffer> {
    const bits = await EdCrypto.deriveBits({ ...algorithm, public: algorithm.public as EdPublicKey }, baseKey, length);
    return bits;
  }

  public async onExportKey(format: KeyFormat, key: EdPrivateKey | EdPublicKey): Promise<ArrayBuffer | JsonWebKey> {
    return EdCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

}