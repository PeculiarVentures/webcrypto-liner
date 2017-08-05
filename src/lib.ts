import { Crypto, nativeCrypto } from "./index";

// Object.freeze(Math);
// Object.freeze(Math.random);
// Object.freeze((Math as any).imul);

if (nativeCrypto) {
    Object.freeze(nativeCrypto.getRandomValues);
}

export const crypto = new Crypto();
