export interface CryptoKeyPair extends NativeCryptoKeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export interface ICryptoKeyOptions {
    algorithm: any;
    type?: string;
    extractable: boolean;
    usages: string[];
}

export class CryptoKey implements NativeCryptoKey {
    public key: any;
    public algorithm: KeyAlgorithm;
    public extractable: boolean;
    public type: string;
    public usages: string[];

    constructor(options: ICryptoKeyOptions) {
        this.algorithm = options.algorithm;
        if (options.type) {
            this.type = options.type;
        }
        this.extractable = options.extractable;
        this.usages = options.usages;
    }
}
