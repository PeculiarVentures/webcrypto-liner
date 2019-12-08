import * as asmCrypto from "asmcrypto.js";
import * as core from "webcrypto-core";
import { PbkdfCryptoKey } from "./key";

export class Pbkdf2Provider extends core.Pbkdf2Provider {

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return new PbkdfCryptoKey(
      algorithm,
      extractable,
      keyUsages,
      core.BufferSourceConverter.toUint8Array(keyData as ArrayBuffer),
    );
  }

  public async onDeriveBits(algorithm: Pbkdf2Params, baseKey: PbkdfCryptoKey, length: number): Promise<ArrayBuffer> {
    let result: Uint8Array;
    const salt = core.BufferSourceConverter.toUint8Array(algorithm.salt);
    const password = baseKey.raw;
    switch ((algorithm.hash as Algorithm).name.toUpperCase()) {
      case "SHA-1":
        result = asmCrypto.Pbkdf2HmacSha1(password, salt, algorithm.iterations, length >> 3);
        break;
      case "SHA-256":
        result = asmCrypto.Pbkdf2HmacSha256(password, salt, algorithm.iterations, length >> 3);
        break;
      case "SHA-512":
        result = asmCrypto.Pbkdf2HmacSha512(password, salt, algorithm.iterations, length >> 3);
        break;
      default:
        throw new core.OperationError(`algorithm.hash: '${(algorithm.hash as Algorithm).name}' hash algorithm is not supported`);
    }
    return core.BufferSourceConverter.toArrayBuffer(result);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is PbkdfCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof PbkdfCryptoKey)) {
      throw new TypeError("key: Is not PbkdfCryptoKey");
    }
  }

}
