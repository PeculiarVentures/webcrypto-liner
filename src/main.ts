import { BrowserInfo } from "./helper";
import { LinerError, Crypto } from "./crypto";

let _w: any = self;
export const browser = BrowserInfo();

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

delete self.crypto;
_w.crypto = new Crypto();