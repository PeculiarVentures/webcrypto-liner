import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as asmCrypto from "asmcrypto.js";
import * as core from "webcrypto-core";
import { nativeCrypto } from "../../native";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider {

  public async onGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    // gat random bytes for key
    const raw = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));

    const key = new HmacCryptoKey(algorithm, extractable, keyUsages, raw);

    return key;
  }

  public async onSign(algorithm: Algorithm, key: HmacCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    let result: Uint8Array;
    switch (key.algorithm.hash.name.toUpperCase()) {
      case "SHA-1":
        result = new asmCrypto.HmacSha1(key.data).result;
        break;
      case "SHA-256":
        result = new asmCrypto.HmacSha256(key.data).result;
        break;
      case "SHA-512":
        result = new asmCrypto.HmacSha512(key.data).result;
        break;
      default:
        throw new core.OperationError("key.algorithm.hash.: Is not recognized");
    }

    return core.BufferSourceConverter.toArrayBuffer(result);
  }

  public async onVerify(algorithm: Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const message = core.BufferSourceConverter.toUint8Array(data);
    let fn: typeof asmCrypto.HmacSha1 | typeof asmCrypto.HmacSha256 | typeof asmCrypto.HmacSha512;
    switch (key.algorithm.hash.name.toUpperCase()) {
      case "SHA-1":
        fn = asmCrypto.HmacSha1;
        break;
      case "SHA-256":
        fn = asmCrypto.HmacSha256;
        break;
      case "SHA-512":
        fn = asmCrypto.HmacSha512;
        break;
      default:
        throw new core.OperationError("key.algorithm.hash.: Is not recognized");
    }
    try {
      // tslint:disable-next-line: no-unused-expression
      new fn(key.data, message);
      return true;
    } catch {
      return false;
    }
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    let key: HmacCryptoKey;

    switch (format.toLowerCase()) {
      case "jwk":
        key = JsonParser.fromJSON(keyData, { targetSchema: HmacCryptoKey });
        break;
      case "raw":
        if (!core.BufferSourceConverter.isBufferSource(keyData)) {
          throw new TypeError("keyData: Is not ArrayBuffer or ArrayBufferView");
        }
        key = new HmacCryptoKey(algorithm, extractable, keyUsages, core.BufferSourceConverter.toUint8Array(keyData));
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    key.algorithm = {
      hash: { name: (algorithm.hash as Algorithm).name },
      name: this.name,
      length: key.data.length << 3,
    };
    key.extractable = extractable;
    key.usages = keyUsages;

    return key;
  }

  public async onExportKey(format: KeyFormat, key: HmacCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        return JsonSerializer.toJSON(key);
      case "raw":
        return new Uint8Array(key.data).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

}
