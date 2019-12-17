import * as core from "webcrypto-core"

export declare const nativeCrypto: core.NativeCrypto;
export declare const nativeSubtle: core.NativeSubtleCrypto;
export declare function setCrypto(crypto: core.NativeSubtleCrypto): void;
export import Crypto = core.NativeCrypto;
export import CryptoKey = core.NativeCryptoKey;

declare global {
  const liner: {
    Crypto: new() => core.NativeCrypto;
    CryptoKey: new () => core.NativeCryptoKey;
    nativeCrypto: core.NativeCrypto;
    nativeSubtle: core.NativeSubtleCrypto;
    setCrypto: (crypto: core.NativeSubtleCrypto) => void;
    crypto: Crypto;
  };
}