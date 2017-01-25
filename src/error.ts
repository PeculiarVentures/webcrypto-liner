import { WebCryptoError } from "webcrypto-core";

export class LinerError extends WebCryptoError {
    code = 10;

    static MODULE_NOT_FOUND = "Module '%1' is not found. Download it from %2";
    static UNSUPPORTED_ALGORITHM = "Unsupported algorithm '%1'";
}