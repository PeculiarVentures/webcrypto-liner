import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import * as asn from "../../asn";
import { concat } from "../../helper";
import { getOidByNamedCurve } from "./helper";
import { EcCryptoKey } from "./key";

export class EcCrypto {

  public static privateUsages: KeyUsage[] = ["sign", "deriveKey", "deriveBits"];
  public static publicUsages: KeyUsage[] = ["verify"];

  public static readonly ASN_ALGORITHM = "1.2.840.10045.2.1";

  public static checkLib() {
    if (typeof (elliptic) === "undefined") {
      throw new core.OperationError("Cannot implement DES mechanism. Add 'https://peculiarventures.github.io/pv-webcrypto-tests/src/elliptic.js' script to your project");
    }
  }

  public static async generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    this.checkLib();

    const key = this.initEcKey(algorithm.namedCurve);
    const ecKey = key.genKeyPair();
    // set key params
    const prvKey = new EcCryptoKey(
      { ...algorithm },
      extractable,
      "private",
      keyUsages.filter((usage) => ~this.privateUsages.indexOf(usage)),
      ecKey,
    );
    const pubKey = new EcCryptoKey(
      { ...algorithm },
      true,
      "public",
      keyUsages.filter((usage) => ~this.publicUsages.indexOf(usage)),
      ecKey,
    );

    return {
      privateKey: prvKey,
      publicKey: pubKey,
    };
  }

  public static checkCryptoKey(key: any) {
    if (!(key instanceof EcCryptoKey)) {
      throw new TypeError("key: Is not EcCryptoKey");
    }
  }

  public static concat(...buf: Uint8Array[]) {
    const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur));
    let offset = 0;
    buf.forEach((item, index) => {
      for (let i = 0; i < item.length; i++) {
        res[offset + i] = item[i];
      }
      offset += item.length;
    });
    return res;
  }

  public static async exportKey(format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    this.checkLib();

    switch (format) {
      case "pkcs8":
        return this.exportPkcs8Key(key);
      case "spki":
        return this.exportSpkiKey(key);
      case "jwk":
        return this.exportJwkKey(key);
      case "raw":
        return new Uint8Array(key.data.getPublic("der")).buffer;
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw, 'pkcs8' or 'spki'");
    }
  }

  public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    this.checkLib();

    let ecKey: EllipticJS.EllipticKeyPair;
    switch (format) {
      case "pkcs8":
        ecKey = this.importPkcs8Key(keyData as ArrayBuffer, algorithm.namedCurve);
        break;
      case "spki":
        ecKey = this.importSpkiKey(keyData as ArrayBuffer, algorithm.namedCurve);
        break;
      case "raw":
        ecKey = this.importEcKey(new asn.EcPublicKey(keyData as ArrayBuffer), algorithm.namedCurve);
        break;
      case "jwk":
        ecKey = this.importJwkKey(keyData as JsonWebKey);
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
    const key = new EcCryptoKey(
      {
        ...algorithm,
      } as EcKeyAlgorithm,
      extractable,
      ecKey.priv ? "private" : "public",
      keyUsages,
      ecKey,
    );
    return key;
  }

  protected static getNamedCurve(wcNamedCurve: string) {
    const crv = wcNamedCurve.toUpperCase();
    let res = "";
    if (["P-256", "P-384", "P-521"].indexOf(crv) > -1) {
      res = crv.replace("-", "").toLowerCase();
    } else if (crv === "K-256") {
      res = "secp256k1";
    } else {
      throw new core.OperationError(`Unsupported named curve '${wcNamedCurve}'`);
    }
    return res;
  }

  private static initEcKey(namedCurve: string) {
    return elliptic.ec(this.getNamedCurve(namedCurve));
  }

  private static exportPkcs8Key(key: EcCryptoKey) {
    const keyInfo = new asn.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = this.ASN_ALGORITHM;
    keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(
      new asn.ObjectIdentifier(getOidByNamedCurve(key.algorithm.namedCurve)),
    );
    keyInfo.privateKey = AsnSerializer.serialize(this.exportEcKey(key));

    return AsnSerializer.serialize(keyInfo);
  }

  private static importPkcs8Key(data: ArrayBuffer, namedCurve: string) {
    const keyInfo = AsnParser.parse(data, asn.PrivateKeyInfo);
    const privateKey = AsnParser.parse(keyInfo.privateKey, asn.EcPrivateKey);
    return this.importEcKey(privateKey, namedCurve);
  }

  private static importSpkiKey(data: ArrayBuffer, namedCurve: string) {
    const keyInfo = AsnParser.parse(data, asn.PublicKeyInfo);
    const publicKey = new asn.EcPublicKey(keyInfo.publicKey);
    return this.importEcKey(publicKey, namedCurve);
  }

  private static exportSpkiKey(key: EcCryptoKey) {
    const publicKey = new asn.EcPublicKey(new Uint8Array(key.data.getPublic("der")).buffer);

    const keyInfo = new asn.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = this.ASN_ALGORITHM;
    keyInfo.publicKeyAlgorithm.parameters = AsnSerializer.serialize(
      new asn.ObjectIdentifier(getOidByNamedCurve(key.algorithm.namedCurve)),
    );
    keyInfo.publicKey = publicKey.value;
    return AsnSerializer.serialize(keyInfo);
  }

  private static importJwkKey(data: JsonWebKey) {
    let key: asn.EcPrivateKey | asn.EcPublicKey;
    if (data.d) {
      // private
      key = JsonParser.fromJSON(data, { targetSchema: asn.EcPrivateKey });
    } else {
      // public
      key = JsonParser.fromJSON(data, { targetSchema: asn.EcPublicKey });
    }
    return this.importEcKey(key, data.crv);
  }

  private static exportJwkKey(key: EcCryptoKey) {
    const asnKey = this.exportEcKey(key);
    const jwk = JsonSerializer.toJSON(asnKey) as JsonWebKey;

    jwk.ext = true;
    jwk.key_ops = key.usages;
    jwk.crv = key.algorithm.namedCurve;
    jwk.kty = "EC";

    return jwk;
  }

  private static exportEcKey(ecKey: EcCryptoKey): asn.EcPrivateKey | asn.EcPublicKey {
    if (ecKey.type === "private") {
      // private
      const privateKey = new asn.EcPrivateKey();
      const point = new Uint8Array(ecKey.data.getPrivate("der").toArray());
      const pointPad = new Uint8Array(this.getPointSize(ecKey.algorithm.namedCurve) - point.length);

      privateKey.privateKey = concat(pointPad, point);
      privateKey.publicKey = new Uint8Array(ecKey.data.getPublic("der"));
      return privateKey;
    } else if (ecKey.data.pub) {
      // public
      return new asn.EcPublicKey(new Uint8Array(ecKey.data.getPublic("der")).buffer);
    } else {
      throw new Error("Cannot get private or public key");
    }
  }

  private static importEcKey(key: asn.EcPrivateKey | asn.EcPublicKey, namedCurve: string) {
    const ecKey = this.initEcKey(namedCurve);

    if (key instanceof asn.EcPublicKey) {
      return ecKey.keyFromPublic(new Uint8Array(key.value));
    }
    return ecKey.keyFromPrivate(new Uint8Array(key.privateKey));
  }

  private static getPointSize(namedCurve: string) {
    switch (namedCurve) {
      case "P-256":
      case "K-256":
        return 32;
      case "P-384":
        return 48;
      case "P-521":
        return 66;
    }
    throw new Error("namedCurve: Is not recognized");
  }

}
