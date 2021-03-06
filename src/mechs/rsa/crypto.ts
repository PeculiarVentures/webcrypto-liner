import { AsnConvert } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { concat } from "../../helper";
import { nativeCrypto, nativeSubtle } from "../../native";
import { RsaCryptoKey } from "./key";

export type AsmCryptoRsaKey = Uint8Array[];

export class RsaCrypto {

  public static RsaSsa = "RSASSA-PKCS1-v1_5";
  public static RsaPss = "RSA-PSS";
  public static RsaOaep = "RSA-OAEP";

  public static privateUsages: KeyUsage[] = ["sign", "decrypt", "unwrapKey"];
  public static publicUsages: KeyUsage[] = ["verify", "encrypt", "wrapKey"];

  /**
   * Tests whether the specified object is RsaCryptoKey and throws a TypeError if it is not
   * @param key The object the test expects to be RsaCryptoKey
   */
  public static checkCryptoKey(key: any): asserts key is RsaCryptoKey {
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not RsaCryptoKey");
    }
  }

  public static async generateKey(algorithm: RsaHashedKeyGenParams | RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const alg: RsaHashedKeyGenParams = {
      name: "RSA-PSS",
      hash: "SHA-256",
      publicExponent: algorithm.publicExponent,
      modulusLength: algorithm.modulusLength,
    };
    // generate keys using native crypto
    const keys = (await nativeSubtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const crypto = new Crypto();

    // create private key
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, algorithm, extractable, keyUsages.filter((o) => this.privateUsages.includes(o)));

    // create public key
    const spki = await crypto.subtle.exportKey("spki", keys.publicKey);
    const publicKey = await crypto.subtle.importKey("spki", spki, algorithm, true, keyUsages.filter((o) => this.publicUsages.includes(o)));

    return { privateKey, publicKey };
  }

  public static async exportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format) {
      case "pkcs8":
        return this.exportPkcs8Key(key);
      case "spki":
        return this.exportSpkiKey(key);
      case "jwk":
        return this.exportJwkKey(key);
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    let asmKey: AsmCryptoRsaKey;
    switch (format) {
      case "pkcs8":
        asmKey = this.importPkcs8Key(keyData as ArrayBuffer);
        break;
      case "spki":
        asmKey = this.importSpkiKey(keyData as ArrayBuffer);
        break;
      case "jwk":
        asmKey = this.importJwkKey(keyData as JsonWebKey);
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
    const key = new RsaCryptoKey(
      {
        publicExponent: asmKey[1][1] === 1
          ? asmKey[1].slice(1)
          : asmKey[1].slice(3),
        modulusLength: asmKey[0].byteLength << 3,
        ...algorithm,
      } as RsaHashedKeyAlgorithm,
      extractable,
      asmKey.length === 2 ? "public" : "private",
      keyUsages,
      asmKey,
    );
    return key;
  }

  public static randomNonZeroValues(data: Uint8Array) {
    data = nativeCrypto.getRandomValues(data);
    return data.map((n) => {
      while (!n) {
        n = nativeCrypto.getRandomValues(new Uint8Array(1))[0];
      }
      return n;
    });
  }

  private static exportPkcs8Key(key: RsaCryptoKey) {
    const keyInfo = new core.asn1.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.privateKeyAlgorithm.parameters = null;
    keyInfo.privateKey = AsnConvert.serialize(this.exportAsmKey(key.data));

    return AsnConvert.serialize(keyInfo);
  }

  private static importPkcs8Key(data: ArrayBuffer) {
    const keyInfo = AsnConvert.parse(data, core.asn1.PrivateKeyInfo);
    const privateKey = AsnConvert.parse(keyInfo.privateKey, core.asn1.RsaPrivateKey);
    return this.importAsmKey(privateKey);
  }

  private static importSpkiKey(data: ArrayBuffer) {
    const keyInfo = AsnConvert.parse(data, core.asn1.PublicKeyInfo);
    const publicKey = AsnConvert.parse(keyInfo.publicKey, core.asn1.RsaPublicKey);
    return this.importAsmKey(publicKey);
  }

  private static exportSpkiKey(key: RsaCryptoKey) {
    const publicKey = new core.asn1.RsaPublicKey();
    publicKey.modulus = key.data[0].buffer;
    publicKey.publicExponent = key.data[1][1] === 1
      ? key.data[1].buffer.slice(1)
      : key.data[1].buffer.slice(3);

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;
    keyInfo.publicKey = AsnConvert.serialize(publicKey);

    return AsnConvert.serialize(keyInfo);
  }

  private static importJwkKey(data: JsonWebKey) {
    let key: core.asn1.RsaPrivateKey | core.asn1.RsaPublicKey;
    if (data.d) {
      // private
      key = JsonParser.fromJSON(data, { targetSchema: core.asn1.RsaPrivateKey });
    } else {
      // public
      key = JsonParser.fromJSON(data, { targetSchema: core.asn1.RsaPublicKey });
    }
    return this.importAsmKey(key);
  }

  private static exportJwkKey(key: RsaCryptoKey) {
    const asnKey = this.exportAsmKey(key.data);
    const jwk = JsonSerializer.toJSON(asnKey) as JsonWebKey;

    jwk.ext = true;
    jwk.key_ops = key.usages;
    jwk.kty = "RSA";
    jwk.alg = this.getJwkAlgorithm(key.algorithm);

    return jwk;
  }

  private static getJwkAlgorithm(algorithm: RsaHashedKeyAlgorithm) {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-OAEP":
        const mdSize = /(\d+)$/.exec(algorithm.hash.name)![1];
        return `RSA-OAEP${mdSize !== "1" ? `-${mdSize}` : ""}`;
      case "RSASSA-PKCS1-V1_5":
        return `RS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      case "RSA-PSS":
        return `PS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      case "RSAES-PKCS1-V1_5":
        return `PS1`;
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  private static exportAsmKey(asmKey: AsmCryptoRsaKey): core.asn1.RsaPrivateKey | core.asn1.RsaPublicKey {
    let key: core.asn1.RsaPrivateKey | core.asn1.RsaPublicKey;
    if (asmKey.length > 2) {
      // private
      const privateKey = new core.asn1.RsaPrivateKey();
      privateKey.privateExponent = asmKey[2].buffer;
      privateKey.prime1 = asmKey[3].buffer;
      privateKey.prime2 = asmKey[4].buffer;
      privateKey.exponent1 = asmKey[5].buffer;
      privateKey.exponent2 = asmKey[6].buffer;
      privateKey.coefficient = asmKey[7].buffer;
      key = privateKey;
    } else {
      // public
      key = new core.asn1.RsaPublicKey();
    }
    key.modulus = asmKey[0].buffer;
    key.publicExponent = asmKey[1][1] === 1
      ? asmKey[1].buffer.slice(1)
      : asmKey[1].buffer.slice(3);

    return key;
  }

  private static importAsmKey(key: core.asn1.RsaPrivateKey | core.asn1.RsaPublicKey) {
    const expPadding = new Uint8Array(4 - key.publicExponent.byteLength);
    const asmKey: AsmCryptoRsaKey = [
      new Uint8Array(key.modulus),
      concat(expPadding, new Uint8Array(key.publicExponent)),
    ];
    if (key instanceof core.asn1.RsaPrivateKey) {
      asmKey.push(new Uint8Array(key.privateExponent));
      asmKey.push(new Uint8Array(key.prime1));
      asmKey.push(new Uint8Array(key.prime2));
      asmKey.push(new Uint8Array(key.exponent1));
      asmKey.push(new Uint8Array(key.exponent2));
      asmKey.push(new Uint8Array(key.coefficient));
    }

    return asmKey;
  }

}
