import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import * as asn from "../../asn";
import { concat } from "../../helper";
import { RsaCryptoKey } from "./key";

export class RsaCrypto {

  public static RsaSsa = "RSASSA-PKCS1-v1_5";
  public static RsaPss = "RSA-PSS";
  public static RsaOaep = "RSA-OAEP";

  public static privateUsages: KeyUsage[] = ["sign", "decrypt", "unwrapKey"];
  public static publicUsages: KeyUsage[] = ["verify", "encrypt", "wrapKey"];

  public static checkLib() {
    if (typeof (asmCrypto) === "undefined") {
      throw new core.OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/asmcrypto.js' script to your project");
    }
  }

  public static checkCryptoKey(key: any) {
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not RsaCryptoKey");
    }
  }

  public static async generateKey(algorithm: RsaHashedKeyGenParams | RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    this.checkLib();

    // prepare data
    const pubExp = algorithm.publicExponent[0] === 3 ? 3 : 65537;

    // generate key
    const rsaKey = asmCrypto.RSA.generateKey(algorithm.modulusLength, pubExp);

    // assign keys
    const keyAlg = { ...algorithm } as RsaHashedKeyAlgorithm;
    if ((algorithm as RsaHashedKeyAlgorithm).hash) {
      const hashAlgorithm = ((algorithm as RsaHashedKeyAlgorithm).hash as Algorithm).name.toUpperCase();
      keyAlg.hash = { name: hashAlgorithm };
    }

    const privateKey: RsaCryptoKey = new RsaCryptoKey(
      keyAlg,
      extractable,
      "private",
      keyUsages.filter((usage) => ~this.privateUsages.indexOf(usage)),
      rsaKey,
    );
    const publicKey: RsaCryptoKey = new RsaCryptoKey(
      keyAlg,
      true,
      "public",
      keyUsages.filter((usage) => ~this.publicUsages.indexOf(usage)),
      rsaKey,
    );

    return { privateKey, publicKey };
  }

  public static async exportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    this.checkLib();

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
    this.checkLib();

    let asmKey: asmCrypto.RsaKey;
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

  private static exportPkcs8Key(key: RsaCryptoKey) {
    const keyInfo = new asn.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.privateKeyAlgorithm.parameters = null;
    keyInfo.privateKey = AsnSerializer.serialize(this.exportAsmKey(key.data));

    return AsnSerializer.serialize(keyInfo);
  }

  private static importPkcs8Key(data: ArrayBuffer) {
    const keyInfo = AsnParser.parse(data, asn.PrivateKeyInfo);
    const privateKey = AsnParser.parse(keyInfo.privateKey, asn.RsaPrivateKey);
    return this.importAsmKey(privateKey);
  }

  private static importSpkiKey(data: ArrayBuffer) {
    const keyInfo = AsnParser.parse(data, asn.PublicKeyInfo);
    const publicKey = AsnParser.parse(keyInfo.publicKey, asn.RsaPublicKey);
    return this.importAsmKey(publicKey);
  }

  private static exportSpkiKey(key: RsaCryptoKey) {
    const publicKey = new asn.RsaPublicKey();
    publicKey.modulus = key.data[0].buffer;
    publicKey.publicExponent = key.data[1][1] === 1
      ? key.data[1].buffer.slice(1)
      : key.data[1].buffer.slice(3);

    const keyInfo = new asn.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;
    keyInfo.publicKey = AsnSerializer.serialize(publicKey);

    return AsnSerializer.serialize(keyInfo);
  }

  private static importJwkKey(data: JsonWebKey) {
    let key: asn.RsaPrivateKey | asn.RsaPublicKey;
    if (data.d) {
      // private
      key = JsonParser.fromJSON(data, { targetSchema: asn.RsaPrivateKey });
    } else {
      // public
      key = JsonParser.fromJSON(data, { targetSchema: asn.RsaPublicKey });
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
      case "RSA-PKCS1":
        return `PS1`;
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  private static exportAsmKey(asmKey: asmCrypto.RsaKey): asn.RsaPrivateKey | asn.RsaPublicKey {
    let key: asn.RsaPrivateKey | asn.RsaPublicKey;
    if (asmKey.length > 2) {
      // private
      const privateKey = new asn.RsaPrivateKey();
      privateKey.privateExponent = asmKey[2].buffer;
      privateKey.prime1 = asmKey[3].buffer;
      privateKey.prime2 = asmKey[4].buffer;
      privateKey.exponent1 = asmKey[5].buffer;
      privateKey.exponent2 = asmKey[6].buffer;
      privateKey.coefficient = asmKey[7].buffer;
      key = privateKey;
    } else {
      // public
      key = new asn.RsaPublicKey();
    }
    key.modulus = asmKey[0].buffer;
    key.publicExponent = asmKey[1][1] === 1
      ? asmKey[1].buffer.slice(1)
      : asmKey[1].buffer.slice(3);

    return key;
  }

  private static importAsmKey(key: asn.RsaPrivateKey | asn.RsaPublicKey) {
    const expPadding = new Uint8Array(4 - key.publicExponent.byteLength);
    const asmKey: asmCrypto.RsaKey = [
      new Uint8Array(key.modulus),
      concat(expPadding, new Uint8Array(key.publicExponent)),
    ];
    if (key instanceof asn.RsaPrivateKey) {
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
