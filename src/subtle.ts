import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import * as asn from "./asn";
import { Debug } from "./debug";
import { Browser, BrowserInfo } from "./helper";
import { CryptoKey } from "./key";
import {
  AesCbcProvider, AesCtrProvider, AesEcbProvider, AesGcmProvider, AesKwProvider,
  DesCbcProvider, DesEde3CbcProvider,
  EcCrypto, EcdhProvider,
  EcdsaProvider,
  Pbkdf2Provider, RsaOaepProvider, RsaPssProvider,
  RsaSsaProvider, Sha1Provider, Sha256Provider, Sha512Provider,
} from "./mechs";
import { getOidByNamedCurve } from "./mechs/ec/helper";
import { nativeCryptoKey, nativeSubtle } from "./native";

type SubtleMethods = keyof core.SubtleCrypto;

export class SubtleCrypto extends core.SubtleCrypto {

  private static readonly methods: SubtleMethods[] = ["digest", "importKey", "exportKey", "sign", "verify", "generateKey", "encrypt", "decrypt", "deriveBits", "deriveKey", "wrapKey", "unwrapKey"];

  public readonly browserInfo = BrowserInfo();

  private constructor() {
    super();

    //#region AES
    this.providers.set(new AesCbcProvider());
    this.providers.set(new AesCtrProvider());
    this.providers.set(new AesEcbProvider());
    this.providers.set(new AesGcmProvider());
    this.providers.set(new AesKwProvider());
    //#endregion

    //#region DES
    this.providers.set(new DesCbcProvider());
    this.providers.set(new DesEde3CbcProvider());
    //#endregion

    //#region RSA
    this.providers.set(new RsaSsaProvider());
    this.providers.set(new RsaPssProvider());
    this.providers.set(new RsaOaepProvider());
    //#endregion

    //#region EC
    this.providers.set(new EcdsaProvider());
    this.providers.set(new EcdhProvider());
    //#endregion

    //#region SHA
    this.providers.set(new Sha1Provider());
    this.providers.set(new Sha256Provider());
    this.providers.set(new Sha512Provider());
    //#endregion

    //#region PBKDF
    this.providers.set(new Pbkdf2Provider());
    //#endregion

  }

  public async digest(...args: any[]) {
    return this.wrapNative("digest", ...args);
  }

  public async importKey(...args: any[]) {
    this.fixFirefoxEcImportPkcs8(args);
    return this.wrapNative("importKey", ...args);
  }

  public async exportKey(...args: any[]) {
    return await this.fixFirefoxEcExportPkcs8(args) ||
      await this.wrapNative("exportKey", ...args);
  }

  public async generateKey(...args: any[]) {
    return this.wrapNative("generateKey", ...args);
  }

  public async sign(...args: any[]) {
    return this.wrapNative("sign", ...args);
  }

  public async verify(...args: any[]) {
    return this.wrapNative("verify", ...args);
  }

  public async encrypt(...args: any[]) {
    return this.wrapNative("encrypt", ...args);
  }

  public async decrypt(...args: any[]) {
    return this.wrapNative("decrypt", ...args);
  }

  public async wrapKey(...args: any[]) {
    return this.wrapNative("wrapKey", ...args);
  }

  public async unwrapKey(...args: any[]) {
    return this.wrapNative("unwrapKey", ...args);
  }

  public async deriveBits(...args: any[]) {
    return this.wrapNative("deriveBits", ...args);
  }

  public async deriveKey(...args: any[]) {
    return this.wrapNative("deriveKey", ...args);
  }

  private async wrapNative(method: string, ...args: any[]) {
    if (~["generateKey", "unwrapKey", "deriveKey", "importKey"].indexOf(method)) {
      this.fixAlgorithmName(args);
    }

    try {
      if (method !== "digest" || !args.some((a) => a instanceof CryptoKey)) {
        Debug.info(`Call native '${method}' method`, args);
        const res = await nativeSubtle[method].apply(nativeSubtle, args);
        return res;
      }
    } catch (e) {
      Debug.warn(`Error on native '${method}' calling. ${e.message}`, e);
    }

    if (method === "deriveBits" || method === "deriveKey") {
      // Cast public keys from algorithm
      for (const arg of args) {
        if (typeof arg === "object" && arg.public && arg.public instanceof nativeCryptoKey) {
          arg.public = await this.castKey(arg.public);
        }
      }
    }

    // Cast native keys to liner keys
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg instanceof nativeCryptoKey) {
        args[i] = await this.castKey(arg);
      }
    }

    return super[method].apply(this, args);
  }

  private async castKey(key: core.NativeCryptoKey) {
    Debug.info("Cast native CryptoKey to linter key.", key);
    if (!key.extractable) {
      throw new Error("Cannot cast unextractable crypto key");
    }

    const provider = this.getProvider(key.algorithm.name);
    const jwk = await this.exportKey("jwk", key);

    return provider.importKey("jwk", jwk, key.algorithm, true, key.usages);
  }

  /**
   * Fixes name of the algorithms. Edge doesn't normilize algorithm names in keys
   * @param args
   */
  private fixAlgorithmName(args: any[]) {
    if (this.browserInfo.name === Browser.Edge) {
      for (let i = 0; i < args.length; i++) {
        const arg = args[0];
        if (typeof arg === "string") {
          // algorithm
          for (const algorithm of this.providers.algorithms) {
            if (algorithm.toLowerCase() === arg.toLowerCase()) {
              args[i] = algorithm;
              break;
            }
          }
        } else if (typeof arg === "object" && typeof arg.name === "string") {
          // algorithm.name
          for (const algorithm of this.providers.algorithms) {
            if (algorithm.toLowerCase() === arg.name.toLowerCase()) {
              arg.name = algorithm;
            }
            if ((typeof arg.hash === "string" && algorithm.toLowerCase() === arg.hash.toLowerCase())
              || (typeof arg.hash === "object" && typeof arg.hash.name === "string" && algorithm.toLowerCase() === arg.hash.name.toLowerCase())) {
              arg.hash = { name: algorithm };
            }
          }
        }
      }
    }
  }

  /**
   * Firefox doesn't support import PKCS8 key for ECDSA/ECDH
   */
  private fixFirefoxEcImportPkcs8(args: any[]) {
    const preparedAlgorithm = this.prepareAlgorithm(args[2]) as EcKeyImportParams;
    const algName = preparedAlgorithm.name.toUpperCase();
    if (this.browserInfo.name === Browser.Firefox
      && args[0] === "pkcs8"
      && ~["ECDSA", "ECDH"].indexOf(algName)
      && ~["P-256", "P-384", "P-521"].indexOf(preparedAlgorithm.namedCurve)) {
      if (!core.BufferSourceConverter.isBufferSource(args[1])) {
        throw new TypeError("data: Is not ArrayBuffer or ArrayBufferView");
      }
      const preparedData = core.BufferSourceConverter.toArrayBuffer(args[1]);

      // Convert PKCS8 to JWK
      const keyInfo = AsnParser.parse(preparedData, asn.PrivateKeyInfo);
      const privateKey = AsnParser.parse(keyInfo.privateKey, asn.EcPrivateKey);
      const jwk: JsonWebKey = JsonSerializer.toJSON(privateKey);
      jwk.ext = true;
      jwk.key_ops = args[4];
      jwk.crv = preparedAlgorithm.namedCurve;
      jwk.kty = "EC";

      args[0] = "jwk";
      args[1] = jwk;
    }
  }

  /**
   * Firefox doesn't support export PKCS8 key for ECDSA/ECDH
   */
  private async fixFirefoxEcExportPkcs8(args: any[]) {
    try {
      if (this.browserInfo.name === Browser.Firefox
        && args[0] === "pkcs8"
        && ~["ECDSA", "ECDH"].indexOf(args[1].algorithm.name)
        && ~["P-256", "P-384", "P-521"].indexOf(args[1].algorithm.namedCurve)) {
        const jwk = await this.exportKey("jwk", args[1]);

        // Convert JWK to PKCS8
        const ecKey = JsonParser.fromJSON(jwk, { targetSchema: asn.EcPrivateKey });

        const keyInfo = new asn.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = EcCrypto.ASN_ALGORITHM;
        keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(
          new asn.ObjectIdentifier(getOidByNamedCurve(args[1].algorithm.namedCurve)),
        );
        keyInfo.privateKey = AsnSerializer.serialize(ecKey);

        return AsnSerializer.serialize(keyInfo);
      }
    } catch (err) {
      Debug.error(err);
      return null;
    }
  }

}
