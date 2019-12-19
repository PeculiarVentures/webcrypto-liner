
import { NativeCryptoKey } from "webcrypto-core";
import { CryptoKey } from "./key";

export class WrappedNativeCryptoKey extends CryptoKey {

  constructor(
    algorithm: KeyAlgorithm,
    extractable: boolean,
    type: KeyType,
    usages: KeyUsage[],
    public nativeKey: NativeCryptoKey) {
    super(algorithm, extractable, type, usages);
  }

}
