
import { NativeCryptoKey } from "webcrypto-core";
import { CryptoKey } from "./key";

export class WrappedNativeCryptoKey extends CryptoKey {

  // tslint:disable-next-line: member-access
  #nativeKey: CryptoKey;

  constructor(
    algorithm: KeyAlgorithm,
    extractable: boolean,
    type: KeyType,
    usages: KeyUsage[],
    nativeKey: NativeCryptoKey) {
    super(algorithm, extractable, type, usages);
    this.#nativeKey = nativeKey;
  }

  // @internal
  public getNative() {
    return this.#nativeKey;
  }

}
