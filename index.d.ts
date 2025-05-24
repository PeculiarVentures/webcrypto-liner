import * as core from "webcrypto-core";

export declare const Crypto: new() => core.NativeCrypto;
export declare const CryptoKey: new() => core.NativeCryptoKey;
export declare const nativeCrypto: core.NativeCrypto;
export declare const nativeSubtle: core.NativeSubtleCrypto;
export declare const crypto: core.NativeCrypto;
export declare function setCrypto(crypto: core.NativeSubtleCrypto): void;

export type Crypto = core.NativeCrypto;
export type CryptoKey = core.NativeCryptoKey;

declare global {
  const liner: typeof import("webcrypto-liner");
}
