import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey, CryptoKeyPair } from "../key";
import { string2buffer, buffer2string, concat } from "../helper";

export class ShaCrypto extends BaseCrypto {

    public static digest(alg: Algorithm, message: Uint8Array) {
        return Promise.resolve()
            .then(() => {
                if (typeof asmCrypto === "undefined") {
                    throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
                }
                switch (alg.name.toUpperCase()) {
                    case AlgorithmNames.Sha1:
                        return asmCrypto.SHA1.bytes(message).buffer;
                    case AlgorithmNames.Sha256:
                        return asmCrypto.SHA256.bytes(message).buffer;
                    default:
                        throw new LinerError(`Not supported algorithm '${alg.name}'`);
                }
            });
    }
}
