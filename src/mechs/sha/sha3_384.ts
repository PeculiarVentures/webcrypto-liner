import * as core from "webcrypto-core";
import { hash384 } from "@stablelib/sha3";

export class Sha3384Provider extends core.ProviderCrypto {
  public name = "SHA3-384";
  public usages: core.ProviderKeyUsage = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return hash384(new Uint8Array(data)).buffer;
  }

}
