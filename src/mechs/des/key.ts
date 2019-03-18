import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";

export class DesCryptoKey extends CryptoKey {
  public algorithm: core.DesKeyAlgorithm;

  constructor(algorithm: core.DesKeyAlgorithm, extractable: boolean, usages: KeyUsage[], public raw: Uint8Array) {
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
      case "DES-CBC":
        return `DES-CBC`;
      case "DES-EDE3-CBC":
        return `3DES-CBC`;
      default:
        throw new core.AlgorithmError("Unsupported algorithm name");
    }
  }

}
