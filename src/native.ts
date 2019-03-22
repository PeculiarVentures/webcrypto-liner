import * as core from "webcrypto-core";

let window: Window;
if (typeof self === "undefined") {
  // NodeJS implementation
  const crypto = require("crypto");
  window = {
    crypto: {
      subtle: {} as any,
      // @ts-ignore
      getRandomValues: (array: ArrayBufferView) => {
        const buf = array.buffer;
        const uint8buf = new Uint8Array(buf);
        const rnd = crypto.randomBytes(uint8buf.length);
        rnd.forEach((octet: number, index: number) => uint8buf[index] = octet);
        return array;
      },
    },
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
