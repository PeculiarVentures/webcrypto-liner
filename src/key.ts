export interface CryptoKeyPair extends NativeCryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export class CryptoKey implements NativeCryptoKey {
    public key: any;
    public algorithm: KeyAlgorithm;
    public extractable: boolean;
    public type: string;
    public usages: string[];
}