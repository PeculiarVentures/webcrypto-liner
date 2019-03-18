import * as core from "webcrypto-core";
import {
  AesCbcProvider, AesEcbProvider, AesGcmProvider, AesCtrProvider,
  DesCbcProvider, DesEde3CbcProvider,
  EcdhProvider, EcdsaProvider,
  Pbkdf2Provider,
  RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha512Provider,
} from "./mechs";
import { nativeSubtle, nativeCryptoKey } from "./native";
import { CryptoKey } from "./key";
import { Debug } from "./debug";

type SubtleMethods = keyof core.SubtleCrypto;

export class SubtleCrypto extends core.SubtleCrypto {

  private static readonly methods: SubtleMethods[] = ["digest", "importKey", "exportKey", "sign", "verify", "generateKey", "encrypt", "decrypt", "deriveBits", "deriveKey", "wrapKey", "unwrapKey"];

  private constructor() {
    super();

    //#region AES
    this.providers.set(new AesCbcProvider());
    this.providers.set(new AesCtrProvider());
    this.providers.set(new AesEcbProvider());
    this.providers.set(new AesGcmProvider());
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
    return this.wrapNative("importKey", ...args);
  }

  public async exportKey(...args: any[]) {
    return this.wrapNative("exportKey", ...args);
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

}
