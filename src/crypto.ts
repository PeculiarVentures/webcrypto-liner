import * as core from "webcrypto-core";
import { SubtleCrypto } from "./subtle";
import { nativeCrypto } from "./native";

export class Crypto extends core.Crypto {

    public subtle = new SubtleCrypto();

    public getRandomValues<T extends ArrayBufferView>(array: T): T {
        return nativeCrypto.getRandomValues(array as any);
    }

}
