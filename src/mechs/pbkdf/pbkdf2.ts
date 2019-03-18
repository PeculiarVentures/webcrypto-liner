import * as core from "webcrypto-core";
import { PbkdfCryptoKey } from "./key";

export class Pbkdf2Provider extends core.Pbkdf2Provider {

  public checkLib() {
    if (typeof (asmCrypto) === "undefined") {
      throw new core.OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/asmcrypto.js' script to your project");
    }
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    this.checkLib();

    return new PbkdfCryptoKey(
      algorithm,
      extractable,
      keyUsages,
      core.BufferSourceConverter.toUint8Array(keyData as ArrayBuffer),
    );
  }

  public async onDeriveBits(algorithm: Pbkdf2Params, baseKey: PbkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    this.checkLib();

    let result: Uint8Array;
    const salt = core.BufferSourceConverter.toUint8Array(algorithm.salt);
    const password = baseKey.raw;
    switch ((algorithm.hash as Algorithm).name.toUpperCase()) {
      case "SHA-1":
        result = asmCrypto.PBKDF2_HMAC_SHA1.bytes(password, salt, algorithm.iterations, length >> 3);
        break;
      case "SHA-256":
        result = asmCrypto.PBKDF2_HMAC_SHA256.bytes(password, salt, algorithm.iterations, length >> 3);
        break;
      default:
        throw new core.OperationError(`algorithm.hash: '${(algorithm.hash as Algorithm).name}' hash algorithm is not supported`);
    }
    return result.buffer;
  }

}
