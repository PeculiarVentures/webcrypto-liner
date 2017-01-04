let _w: any;
if (typeof self === "undefined") {
    const crypto = require("crypto");
    _w = {
        crypto: {
            subtle: {},
            getRandomValues: (array: ArrayBufferView) => {
                let buf = array.buffer;
                let uint8buf = new Uint8Array(buf);
                const rnd = crypto.randomBytes(uint8buf.length);
                rnd.forEach((octet: number, index: number) => uint8buf[index] = octet);
                return array;
            }
        }
    };
}
else
    _w = self;

export const nativeCrypto: NativeCrypto = _w.msCrypto || _w.crypto;
export const nativeSubtle: NativeSubtleCrypto = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;