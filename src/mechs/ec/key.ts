/// <reference path="../../typings/elliptic.d.ts" />

import { CryptoKey } from "../../key";

export class EcCryptoKey extends CryptoKey {

  public algorithm: EcKeyAlgorithm;

  constructor(algorithm: EcKeyAlgorithm, extractable: boolean, type: KeyType, usages: KeyUsage[], public data: EllipticJS.EllipticKeyPair) {
    super(algorithm, extractable, type, usages);
  }
}
