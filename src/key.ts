import * as core from "webcrypto-core";

export class CryptoKey extends core.CryptoKey {
  public algorithm: KeyAlgorithm;
  constructor(
    algorithm: KeyAlgorithm,
    public extractable: boolean,
    public type: KeyType,
    public usages: KeyUsage[],
  ) {
    super();
    this.algorithm = { ...algorithm };
  }
}
