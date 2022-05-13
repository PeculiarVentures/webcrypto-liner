import * as core from "webcrypto-core";
import { EdCrypto } from "./crypto";
import { EdPrivateKey } from "./private_key";
import { EdPublicKey } from "./public_key";

export class EdDsaProvider extends core.EdDsaProvider {

  public namedCurves: string[] = ["Ed25519"];

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const keys = await EdCrypto.generateKey(
      {
        name: this.name,
        namedCurve: algorithm.namedCurve.replace(/^ed/i, "Ed"),
      },
      extractable,
      keyUsages);

    return keys;
  }

  public async onSign(algorithm: EcdsaParams, key: EdPrivateKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return EdCrypto.sign(algorithm, key, new Uint8Array(data));
  }

  public async onVerify(algorithm: EcdsaParams, key: EdPublicKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return EdCrypto.verify(algorithm, key, new Uint8Array(signature), new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: EdPrivateKey | EdPublicKey): Promise<ArrayBuffer | JsonWebKey> {
    return EdCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKey> {
    const key = await EdCrypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

}