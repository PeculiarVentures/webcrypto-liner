import { Crypto, nativeCrypto } from "./index";

const w = self as any;

Object.freeze(Math);
Object.freeze(Math.random);
Object.freeze((Math as any).imul);

if (nativeCrypto) {
    Object.freeze(nativeCrypto.getRandomValues);
}

delete (self as any).crypto;
w.crypto = new Crypto();
Object.freeze(w.crypto);

export const crypto = w.crypto;
