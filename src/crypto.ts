import { SubtleCrypto } from "./subtle";
import { nativeCrypto } from "./init";

export class Crypto {

    public subtle = new SubtleCrypto();

    public getRandomValues<T extends ArrayBufferView>(array: T): T {
        return nativeCrypto.getRandomValues(array as any) as any;
    }

}
