import { LinerError } from "./error";

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

function WrapFunction(subtle: any, name: string) {
    const fn = subtle[name];
    subtle[name] = function () {
        const _args = arguments;
        return new Promise((resolve, reject) => {
            let op: any = fn.apply(subtle, _args);
            op.oncomplete = (e: any) => {
                console.log("Complited");
                resolve(e.target.result);
            };
            op.onerror = (e: any) => {
                console.log("Error");
                reject(`Error on running '${name}' function`);
            };
        });
    };
}

if (_w.msCrypto) {
    if (!_w.Promise)
        throw new LinerError(LinerError.MODULE_NOT_FOUND, "Promise", "https://www.promisejs.org");
    WrapFunction(nativeSubtle, "generateKey");
    WrapFunction(nativeSubtle, "digest");
    WrapFunction(nativeSubtle, "sign");
    WrapFunction(nativeSubtle, "verify");
    WrapFunction(nativeSubtle, "encrypt");
    WrapFunction(nativeSubtle, "decrypt");
    WrapFunction(nativeSubtle, "importKey");
    WrapFunction(nativeSubtle, "exportKey");
    WrapFunction(nativeSubtle, "wrapKey");
    WrapFunction(nativeSubtle, "unwrapKey");
    WrapFunction(nativeSubtle, "deriveKey");
    WrapFunction(nativeSubtle, "deriveBits");
}

// fix: Math.imul for IE
if (!(Math as any).imul)
    (Math as any).imul = function imul(a: number, b: number) {
        let ah = (a >>> 16) & 0xffff;
        let al = a & 0xffff;
        let bh = (b >>> 16) & 0xffff;
        let bl = b & 0xffff;
        return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0) | 0);
    };