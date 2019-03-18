import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";

export class AesCryptoKey extends CryptoKey {
  public algorithm: AesKeyAlgorithm;

  constructor(algorithm: AesKeyAlgorithm, extractable: boolean, usages: KeyUsage[], public raw: Uint8Array) {
    super(algorithm, extractable, "secret", usages);
  }

  public toJSON() {
    const jwk: JsonWebKey = {
      kty: "oct",
      alg: this.getJwkAlgorithm(),
      k: Convert.ToBase64Url(this.raw),
      ext: this.extractable,
      key_ops: this.usages,
    };
    return jwk;
  }

  private getJwkAlgorithm() {
    switch (this.algorithm.name.toUpperCase()) {
      case "AES-CBC":
        return `A${this.algorithm.length}CBC`;
      case "AES-CTR":
        return `A${this.algorithm.length}CTR`;
      case "AES-GCM":
        return `A${this.algorithm.length}GCM`;
      case "AES-ECB":
        return `A${this.algorithm.length}ECB`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }
}
