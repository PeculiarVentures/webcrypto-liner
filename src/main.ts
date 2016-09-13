type NativeCrypto = Crypto;
type NativeSubtleCrypto = SubtleCrypto;

namespace webcrypto.liner {


    let _w: any = window;

    export const nativeCrypto: NativeCrypto = _w.crypto || _w.msCrypto;
    export const nativeSubtle = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;
    export const browser = BrowserInfo();


    if (_w.msCrypto) {
        if (!_w.Promise)
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "Promise", "https://www.promisejs.org");
        function WrapFunction(subtle: any, name: string) {
            const fn = subtle[name];
            subtle[name] = function () {
                const _args = arguments;
                return new Promise((resolve, reject) => {
                    let op: any = fn.apply(subtle, _args);
                    op.oncomplete = (e: any) => {
                        console.log("Complited");
                        resolve(e.target.result);
                    }
                    op.onerror = (e: any) => {
                        console.log("Error");
                        reject(`Error on running '${name}' function`);
                    }
                });
            };
        }
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

    delete window.crypto;
    _w.crypto = new Crypto();

}