import * as core from "webcrypto-core";
import { hash512 } from "@stablelib/sha3";

export class Sha3512Provider extends core.ProviderCrypto {
  public name = "SHA3-512";
  public usages: core.ProviderKeyUsage = [];

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return hash512(new Uint8Array(data)).buffer;
  }

}
