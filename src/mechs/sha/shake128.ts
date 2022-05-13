import * as core from "webcrypto-core";
import { SHAKE128 } from "@stablelib/sha3";

export class Shake128Provider extends core.Shake128Provider {

  public async onDigest(algorithm: Required<core.ShakeParams>, data: ArrayBuffer): Promise<ArrayBuffer> {
    const output = new Uint8Array(algorithm.length);
    new SHAKE128().update(new Uint8Array(data)).stream(output);

    return output.buffer;
  }

}
