import { IJsonConvertible } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";
import * as elliptic from "elliptic";
import { generateKeyPair } from 'curve25519-js';
import { Convert } from "pvtsutils";
import { generateEllipticKeys } from "./helper";

export class EdPrivateKey extends CryptoKey implements IJsonConvertible {
  public algorithm!: EcKeyAlgorithm;

  public constructor(algorithm: EcKeyAlgorithm, extractable: boolean, usages: KeyUsage[], public data: EllipticJS.EllipticKeyPair) {
    super(algorithm, extractable, "private", usages)
  }

  public toJSON() {
    const json: JsonWebKey = {
      kty: "OKP",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, {
      d: Convert.ToBase64Url(Convert.FromHex(/^ed/i.test(json.crv) ? this.data.getSecret("hex") : this.data.getPrivate("hex"))),
    });
  }

  public fromJSON(json: JsonWebKey) {
    if (!json.d) {
      throw new core.OperationError(`Cannot get private data from JWK. Property 'd' is required`);
    }
    if (!json.crv) {
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }

    const hexPrivateKey = Convert.ToHex(Convert.FromBase64Url(json.d));
    if (/^ed/i.test(json.crv)) {
      const eddsa = new elliptic.eddsa(json.crv.toLowerCase());
      this.data = eddsa.keyFromSecret(hexPrivateKey);
    } else {
      this.data = generateEllipticKeys(new Uint8Array(Convert.FromBase64Url(json.d)));
    }

    return this;
  }

}
