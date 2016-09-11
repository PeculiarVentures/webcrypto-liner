declare type NativeCryptoKey = CryptoKey;
declare type NativeCryptoKeyPair = CryptoKeyPair;

namespace webcrypto.liner {

    export interface CryptoKeyPair extends NativeCryptoKeyPair {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }

    export class CryptoKey implements NativeCryptoKey {
        key: any;
        algorithm: KeyAlgorithm;
        extractable: boolean;
        type: string;
        usages: string[];
    }

}