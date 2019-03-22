import { CryptoKey } from "../../key";

export class PbkdfCryptoKey extends CryptoKey {

  constructor(algorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[], public raw: Uint8Array) {
    super(algorithm, extractable, "secret", usages);
  }

}
