import { CryptoKey } from "../../key";
import { AsmCryptoRsaKey } from "./crypto";

export class RsaCryptoKey extends CryptoKey {

  public algorithm: RsaHashedKeyAlgorithm;

  constructor(algorithm: RsaHashedKeyAlgorithm, extractable: boolean, type: KeyType, usages: KeyUsage[], public data: AsmCryptoRsaKey) {
    super(algorithm, extractable, type, usages);
  }
}
