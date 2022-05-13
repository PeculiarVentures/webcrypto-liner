import * as core from "webcrypto-core";
import { hash256 } from "@stablelib/sha3";

export class Sha3256Provider extends core.ProviderCrypto {
  public name = "SHA3-256";
  public usages: core.ProviderKeyUsage = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return hash256(new Uint8Array(data)).buffer;
  }

}
