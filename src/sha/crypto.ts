import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import { LinerError } from "../crypto";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";

export class ShaCrypto extends BaseCrypto {
    static digest(alg: Algorithm, message: Uint8Array) {
        return new Promise<ArrayBuffer>(resolve => {
            if (typeof asmCrypto === "undefined")
                throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.Sha1:
                    resolve(asmCrypto.SHA1.bytes(message).buffer);
                    break;
                case AlgorithmNames.Sha256:
                    resolve(asmCrypto.SHA256.bytes(message).buffer);
                    break;
                default:
                    throw new LinerError(`Not supported algorithm '${alg.name}'`);
            }

        });
    }
}