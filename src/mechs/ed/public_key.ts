import { AsnConvert } from "@peculiar/asn1-schema";
import { IJsonConvertible } from "@peculiar/json-schema";
import * as elliptic from "elliptic";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";
import { getOidByNamedCurve } from "./helper";

export class EdPublicKey extends CryptoKey implements IJsonConvertible {

  public algorithm!: EcKeyAlgorithm;

  public constructor(algorithm: EcKeyAlgorithm, extractable: boolean, usages: KeyUsage[], public data: EllipticJS.EllipticKeyPair) {
    super(algorithm, extractable, "public", usages)
  }

  public toJSON() {
    const json: JsonWebKey = {
      kty: "OKP",
      crv: this.algorithm.namedCurve,
      key_ops: this.usages,
      ext: this.extractable,
    };

    return Object.assign(json, {
      x: Convert.ToBase64Url(Convert.FromHex(this.data.getPublic("hex"))),
    });
  }

  public fromJSON(json: JsonWebKey) {
    if (!json.crv) {
      throw new core.OperationError(`Cannot get named curve from JWK. Property 'crv' is required`);
    }
    if (!json.x) {
      throw new core.OperationError(`Cannot get property from JWK. Property 'x' is required`);
    }

    const hexPublicKey = Convert.ToHex(Convert.FromBase64Url(json.x));
    if (/^ed/i.test(json.crv)) {
      const eddsa = new elliptic.eddsa(json.crv.toLowerCase());
      this.data = eddsa.keyFromPublic(hexPublicKey, "hex");
    } else {
      const ecdhEs = elliptic.ec(json.crv.replace(/^x/i, "curve"));
      this.data = ecdhEs.keyFromPublic(hexPublicKey, "hex");
    }

    return this;
  }
}
