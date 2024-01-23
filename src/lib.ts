import { Crypto, nativeCrypto } from "./index";
import "./init";

if (nativeCrypto) {
    Object.freeze(nativeCrypto.getRandomValues);
}

export const crypto = new Crypto();
export * from ".";
