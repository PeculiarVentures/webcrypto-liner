if (typeof self !== "object") {
    const nodeCrypto = require("crypto");
    /**
     * Add `self` to NodeJS global object
     */
    const _g = global as any;
    _g.self = {
        crypto: {
            subtle: {},
            // Add random function for NodeJS crypto implementation 
            getRandomValues: (array: ArrayBufferView) =>
                nodeCrypto.randomBytes(array.byteLength)
        }
    };

}

let _w: any = self;

export const nativeCrypto: NativeCrypto = _w.msCrypto || _w.crypto;
export const nativeSubtle: NativeSubtleCrypto = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;