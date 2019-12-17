import * as core from "webcrypto-core";
import { nativeCrypto } from "./native";
import { SubtleCrypto } from "./subtle";

export class Crypto extends core.Crypto {

    public get nativeCrypto() {
        return nativeCrypto;
    }

    public subtle = new SubtleCrypto();

    public getRandomValues<T extends ArrayBufferView>(array: T): T {
        return nativeCrypto.getRandomValues(array as any);
    }

}
