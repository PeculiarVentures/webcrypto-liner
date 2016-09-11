namespace webcrypto.liner.rsa {

    declare class jsSHA {
        constructor(alg: string, type: "TEXT" | "HEX" | "B64");

        update(msg: string): void;
        getHash(type: "TEXT" | "HEX" | "B64"): string;

    };

    function b2s(message: Uint8Array) {
        return String.fromCharCode.apply(null, message);
    }

    function s2b(message: string) {
        let buf = new ArrayBuffer(message.length);
        let bufView = new Uint8Array(buf);
        for (let i = 0; i < message.length; i++) {
            bufView[i] = message.charCodeAt(i);
        }
        return buf;
    }
    export class ShaCrypto extends BaseCrypto {
        static digest(alg: Algorithm, message: Uint8Array) {
            return new Promise<ArrayBuffer>(resolve => {
                if (typeof jsSHA === "undefined")
                    throw new ShimError(ShimError.MODULE_NOT_FOUND, "jsSHA", "https://github.com/Caligatio/jsSHA");
                let digest = new jsSHA(alg.name.toUpperCase(), "TEXT");
                digest.update(b2s(message));
                let hash = atob(digest.getHash("B64"));
                resolve(s2b(hash));
            });
        }
    }
}