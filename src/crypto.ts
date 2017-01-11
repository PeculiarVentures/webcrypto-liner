import { SubtleCrypto } from "./subtle";
import { nativeCrypto } from "./init";

export class Crypto {

    subtle = new SubtleCrypto();
    getRandomValues(array: ArrayBufferView): ArrayBufferView {
        return nativeCrypto.getRandomValues(array);
    }

}