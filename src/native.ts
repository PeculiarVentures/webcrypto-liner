import * as core from "webcrypto-core";

let window: any;
if (typeof self === "undefined") {
  // NodeJS implementation
  const { Crypto } = require("@peculiar/webcrypto");
  window = {
    crypto: new Crypto(),
  };
} else {
  window = self;
}

export const nativeCrypto: core.NativeCrypto =
  (window as any).msCrypto  // IE
  || window.crypto          // other browsers
  || {};                    // if crypto is empty
export let nativeSubtle: core.NativeSubtleCrypto | null = null;
try {
  nativeSubtle = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;
} catch (err) {
  console.warn("Cannot get subtle from crypto", err);
  // Safari throws error on crypto.webkitSubtle in Worker
}
