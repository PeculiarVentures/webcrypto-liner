import * as core from "webcrypto-core";

let window: any = {};
if (typeof self !== "undefined") {
  window = self;
}

export let nativeCrypto: core.NativeCrypto =
  window["msCrypto"]  // IE
  || window.crypto          // other browsers
  || {};                    // if crypto is empty
export let nativeSubtle: core.NativeSubtleCrypto | null = null;
try {
  nativeSubtle = nativeCrypto?.subtle || nativeCrypto?.["webkitSubtle"] || null;
} catch (err) {
  console.warn("Cannot get subtle from crypto", err);
  // Safari throws error on crypto.webkitSubtle in Worker
}

export function setCrypto(crypto: Crypto) {
  nativeCrypto = crypto;
  nativeSubtle = crypto.subtle;
}
