import * as core from "webcrypto-core";

export class ShaCrypto {

  public static checkLib() {
    if (typeof (asmCrypto) === "undefined") {
      throw new core.OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/asmcrypto.js' script to your project");
    }
  }

  public static async digest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    this.checkLib();

    const mech = asmCrypto[algorithm.name.replace("-", "")] as typeof asmCrypto.SHA1;
    return mech.bytes(data).buffer;
  }
}
