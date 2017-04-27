import { SubtleCrypto } from "./subtle";
import { nativeCrypto } from "./init";

export class Crypto {

    public subtle = new SubtleCrypto();

    public getRandomValues(array: ArrayBufferView): ArrayBufferView {
        return nativeCrypto.getRandomValues(array);
    }

}
