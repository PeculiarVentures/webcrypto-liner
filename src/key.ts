import * as core from "webcrypto-core";

export class CryptoKey extends core.CryptoKey {
  public algorithm: KeyAlgorithm;
  constructor(
    algorithm: KeyAlgorithm,
    public extractable: boolean,
    public type: KeyType,
    public usages: KeyUsage[],
  ) {
    super();
    this.algorithm = { ...algorithm };
  }
}

// export class CryptoKey implements NativeCryptoKey {
//     public key: any;
//     public algorithm: KeyAlgorithm;
//     public extractable: boolean;
//     public type: KeyType;
//     public usages: KeyUsage[];

//     constructor(options: ICryptoKeyOptions) {
//         this.algorithm = options.algorithm;
//         if (options.type) {
//             this.type = options.type;
//         }
//         this.extractable = options.extractable;
//         this.usages = options.usages;
//     }

//     public copy(usages: KeyUsage[]) {
//         const { algorithm, type, extractable } = this;
//         const key = new CryptoKey({ algorithm, type, extractable, usages });
//         key.key = this.key;
//         return key;
//     }
// }
