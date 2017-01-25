import { Crypto, nativeCrypto } from "./index";

let _w = self as any;

Object.freeze(Math);
Object.freeze(Math.random);
Object.freeze((Math as any).imul);

if (nativeCrypto)
    Object.freeze(nativeCrypto.getRandomValues);

delete self.crypto;
_w.crypto = new Crypto();