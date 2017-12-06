import { SubtleCrypto } from "./subtle";
import { nativeCrypto } from "./init";

export class Crypto {

    public subtle = new SubtleCrypto();

    public getRandomValues<T extends Int8Array | Uint8ClampedArray | Uint8Array | Int16Array | Uint16Array | Int32Array | Uint32Array>(array: T): T {
        return nativeCrypto.getRandomValues(array);
    }

}
