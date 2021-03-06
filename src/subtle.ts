import { AsnConvert } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import { BufferSourceConverter, Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Debug } from "./debug";
import { Browser, BrowserInfo } from "./helper";
import { CryptoKey } from "./key";
import {
  AesCbcProvider, AesCtrProvider, AesEcbProvider, AesGcmProvider, AesKwProvider,
  DesCbcProvider, DesEde3CbcProvider,
  EcCrypto, EcdhProvider,
  EcdsaProvider,
  HmacProvider,
  Pbkdf2Provider,
  RsaEsProvider, RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha512Provider,
  EdDsaProvider, EcdhEsProvider,
} from "./mechs";
import { getOidByNamedCurve } from "./mechs/ec/helper";
import { nativeSubtle } from "./native";
import { WrappedNativeCryptoKey } from "./wrapped_native_key";

type SubtleMethods = keyof core.SubtleCrypto;

export class SubtleCrypto extends core.SubtleCrypto {

  private static readonly methods: SubtleMethods[] = ["digest", "importKey", "exportKey", "sign", "verify", "generateKey", "encrypt", "decrypt", "deriveBits", "deriveKey", "wrapKey", "unwrapKey"];

  /**
   * Returns true if key is CryptoKey and is not liner key
   * > WARN Some browsers doesn't have CryptKey class in `self`.
   * @param key
   */
  private static isAnotherKey(key: any): key is core.NativeCryptoKey {
    if (typeof key === "object"
      && typeof key.type === "string"
      && typeof key.extractable === "boolean"
      && typeof key.algorithm === "object") {
      return !(key instanceof CryptoKey);
    }
    return false;
  }

  public readonly browserInfo = BrowserInfo();

  public constructor() {
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
    this.providers.set(new RsaEsProvider());
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

    //#region HMAC
    this.providers.set(new HmacProvider());
    //#endregion

    //#region EdDSA
    this.providers.set(new EdDsaProvider());
    //#endregion

    //#region ECDH-ES
    // TODO Elliptic.js has got issue (https://github.com/indutny/elliptic/issues/243). Uncomment the next line after fix
    // this.providers.set(new EcdhEsProvider());
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

  private async wrapNative(method: SubtleMethods, ...args: any[]) {
    if (~["generateKey", "unwrapKey", "deriveKey", "importKey"].indexOf(method)) {
      this.fixAlgorithmName(args);
    }

    try {
      if (method !== "digest" || !args.some((a) => a instanceof CryptoKey)) {
        const nativeArgs = this.fixNativeArguments(method, args);

        Debug.info(`Call native '${method}' method`, nativeArgs);
        const res = await nativeSubtle[method].apply(nativeSubtle, nativeArgs);

        return this.fixNativeResult(method, args, res);
      }
    } catch (e) {
      Debug.warn(`Error on native '${method}' calling. ${e.message}`, e);
    }

    if (method === "wrapKey") {
      try {
        Debug.info(`Trying to wrap key by using native functions`, args);
        // wrapKey(format, key, wrappingKey, wrapAlgorithm);
        // indexes    0     1        2             3
        const data = await this.exportKey(args[0], args[1]);
        const keyData = (args[0] === "jwk") ? Convert.FromUtf8String(JSON.stringify(data)) : data;
        const res = await this.encrypt(args[3], args[2], keyData);
        return res;
      } catch (e) {
        Debug.warn(`Cannot wrap key by native functions. ${e.message}`, e);
      }
    }

    if (method === "unwrapKey") {
      try {
        Debug.info(`Trying to unwrap key by using native functions`, args);
        // unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages);
        // indexes     0          1            2               3                   4                 5           6
        const data = await this.decrypt(args[3], args[2], args[1]);
        const keyData = (args[0] === "jwk") ? JSON.parse(Convert.ToUtf8String(data)) : data;
        const res = await this.importKey(args[0], keyData, args[4], args[5], args[6]);
        return res;
      } catch (e) {
        Debug.warn(`Cannot unwrap key by native functions. ${e.message}`, e);
      }
    }

    if (method === "deriveKey") {
      try {
        Debug.info(`Trying to derive key by using native functions`, args);
        const data = await this.deriveBits(args[0], args[1], args[2].length);
        const res = await this.importKey("raw", data, args[2], args[3], args[4]);
        return res;
      } catch (e) {
        Debug.warn(`Cannot derive key by native functions. ${e.message}`, e);
      }
    }

    if (method === "deriveBits" || method === "deriveKey") {
      // Cast public keys from algorithm
      for (const arg of args) {
        if (typeof arg === "object" && arg.public && SubtleCrypto.isAnotherKey(arg.public)) {
          arg.public = await this.castKey(arg.public);
        }
      }
    }

    // Cast native keys to liner keys
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (SubtleCrypto.isAnotherKey(arg)) {
        args[i] = await this.castKey(arg);
      }
    }

    return super[method].apply(this, args);
  }

  private fixNativeArguments(method: SubtleMethods, args: any[]) {
    const res = [...args];
    if (method === "importKey") {
      if (this.browserInfo.name === Browser.IE && res[0]?.toLowerCase?.() === "jwk" && !BufferSourceConverter.isBufferSource(res[1])) {
        // IE11 uses ArrayBuffer instead of JSON object
        res[1] = Convert.FromUtf8String(JSON.stringify(res[1]));
      }
    }

    if (this.browserInfo.name === Browser.IE && args[1] instanceof WrappedNativeCryptoKey) {
      // Fix algs for IE11
      switch (method) {
        case "sign":
        case "verify":
        case "encrypt":
        case "decrypt":
          res[0] = { ...this.prepareAlgorithm(res[0]), hash: (res[1]?.algorithm as RsaHashedKeyAlgorithm)?.hash?.name };
          break;
        case "wrapKey":
        case "unwrapKey":
          res[4] = { ...this.prepareAlgorithm(res[4]), hash: (res[3]?.algorithm as RsaHashedKeyAlgorithm)?.hash?.name };
          break;
      }
    }

    for (let i = 0; i < res.length; i++) {
      const arg = res[i];
      if (arg instanceof WrappedNativeCryptoKey) {
        // Convert wrapped key to Native CryptoKey
        res[i] = arg.getNative();
      }
    }

    return res;
  }

  private fixNativeResult(method: SubtleMethods, args: any[], res: any): any {
    if (this.browserInfo.name === Browser.IE) {
      if (method === "exportKey") {
        if (args[0]?.toLowerCase?.() === "jwk" && res instanceof ArrayBuffer) {
          // IE11 uses ArrayBuffer instead of JSON object
          return JSON.parse(Convert.ToUtf8String(res));
        }
      }
      // wrap IE11 native key
      if ("privateKey" in res) {
        const privateKeyUsages = ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"];
        const publicKeyUsages = ["verify", "encrypt", "wrapKey"];
        return {
          privateKey: this.wrapNativeKey(res.privateKey, args[0], args[1], args[2].filter((o: string) => privateKeyUsages.includes(o))),
          publicKey: this.wrapNativeKey(res.publicKey, args[0], args[1], args[2].filter((o: string) => publicKeyUsages.includes(o))),
        };
      } else if ("extractable" in res) {
        let algorithm: Algorithm;
        let usages: KeyUsage[];
        switch (method) {
          case "importKey":
            algorithm = args[2];
            usages = args[4];
            break;
          case "unwrapKey":
            algorithm = args[4];
            usages = args[6];

            break;
          case "generateKey":
            algorithm = args[0];
            usages = args[2];
            break;

          default:
            throw new core.OperationError("Cannot wrap native key. Unsupported method in use");
        }
        return this.wrapNativeKey(res, algorithm, res.extractable, usages);
      }
    }

    return res;
  }

  private wrapNativeKey(key: core.NativeCryptoKey, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): core.NativeCryptoKey {
    if (this.browserInfo.name === Browser.IE) {
      const algs = [
        "RSASSA-PKCS1-v1_5", "RSA-PSS", "RSA-OAEP",
        "AES-CBC", "AES-CTR", "AES-KW", "HMAC",
      ];
      const index = algs.map((o) => o.toLowerCase()).indexOf(key.algorithm.name.toLowerCase());
      if (index !== -1) {
        const alg = this.prepareAlgorithm(algorithm);
        const newAlg: any = {
          ...key.algorithm,
          name: algs[index],
        };
        if (core.SubtleCrypto.isHashedAlgorithm(alg)) {
          newAlg.hash = {
            name: (alg.hash as any).name.toUpperCase(),
          };
        }
        Debug.info(`Wrapping ${algs[index]} crypto key to WrappedNativeCryptoKey`);
        return new WrappedNativeCryptoKey(newAlg, extractable, key.type, keyUsages, key);
      }
    }
    return key;
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
      const keyInfo = AsnConvert.parse(preparedData, core.asn1.PrivateKeyInfo);
      const privateKey = AsnConvert.parse(keyInfo.privateKey, core.asn1.EcPrivateKey);
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
        const ecKey = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.EcPrivateKey });

        const keyInfo = new core.asn1.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = EcCrypto.ASN_ALGORITHM;
        keyInfo.privateKeyAlgorithm.parameters = AsnConvert.serialize(
          new core.asn1.ObjectIdentifier(getOidByNamedCurve(args[1].algorithm.namedCurve)),
        );
        keyInfo.privateKey = AsnConvert.serialize(ecKey);

        return AsnConvert.serialize(keyInfo);
      }
    } catch (err) {
      Debug.error(err);
      return null;
    }
  }

}
