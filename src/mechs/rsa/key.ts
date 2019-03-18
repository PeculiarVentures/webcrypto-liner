import { CryptoKey } from "../../key";

export class RsaCryptoKey extends CryptoKey {

  public algorithm: RsaHashedKeyAlgorithm;

  constructor(algorithm: RsaHashedKeyAlgorithm, extractable: boolean, type: KeyType, usages: KeyUsage[], public data: asmCrypto.RsaKey) {
    super(algorithm, extractable, type, usages);
  }
}
