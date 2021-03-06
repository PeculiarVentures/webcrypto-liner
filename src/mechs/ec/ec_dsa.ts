import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

/**
 * Converts buffer to number array
 * @param buffer ArrayBuffer or ArrayBufferView
 */
export function b2a(buffer: ArrayBuffer | ArrayBufferView) {
  const buf = new Uint8Array(buffer as ArrayBuffer);
  const res: number[] = [];
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < buf.length; i++) {
    res.push(buf[i]);
  }
  return res;
}

function hex2buffer(hexString: string, padded?: boolean) {
  if (hexString.length % 2) {
    hexString = "0" + hexString;
  }
  let res = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i++) {
    const c = hexString.slice(i, ++i + 1);
    res[(i - 1) / 2] = parseInt(c, 16);
  }
  // BN padding
  if (padded) {
    let len = res.length;
    len = len > 32 ? len > 48 ? 66 : 48 : 32;
    if (res.length < len) {
      res = EcCrypto.concat(new Uint8Array(len - res.length), res);
    }
  }
  return res;
}

function buffer2hex(buffer: Uint8Array, padded?: boolean): string {
  let res = "";
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < buffer.length; i++) {
    const char = buffer[i].toString(16);
    res += char.length % 2 ? "0" + char : char;
  }

  // BN padding
  if (padded) {
    let len = buffer.length;
    len = len > 32 ? len > 48 ? 66 : 48 : 32;
    if ((res.length / 2) < len) {
      res = new Array(len * 2 - res.length + 1).join("0") + res;
    }
  }

  return res;
}

export class EcdsaProvider extends core.EcdsaProvider {

  public async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return EcCrypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<ArrayBuffer | JsonWebKey> {
    return EcCrypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return EcCrypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public async onSign(algorithm: EcdsaParams, key: EcCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    EcCrypto.checkLib();

    // get digests
    const crypto = new Crypto();
    let array;

    const hash = await crypto.subtle.digest(algorithm.hash, data);
    array = b2a(hash);
    const signature = await key.data.sign(array);
    const hexSignature = buffer2hex(signature.r.toArray(), true) + buffer2hex(signature.s.toArray(), true);
    return hex2buffer(hexSignature).buffer;
  }

  public async onVerify(algorithm: EcdsaParams, key: EcCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    EcCrypto.checkLib();

    const crypto = new Crypto();

    const sig = {
      r: new Uint8Array(signature.slice(0, signature.byteLength / 2)),
      s: new Uint8Array(signature.slice(signature.byteLength / 2)),
    };

    // get digest
    const hashedData = await crypto.subtle.digest(algorithm.hash, data);
    const array = b2a(hashedData);

    return key.data.verify(array, sig);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage: KeyUsage): asserts key is EcCryptoKey {
    super.checkCryptoKey(key, keyUsage);
    EcCrypto.checkCryptoKey(key);
  }

}
