import { IJsonConvertible } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";
import * as elliptic from "elliptic";
import { sharedKey, generateKeyPair } from 'curve25519-js';
import BN from "bn.js";
import { Convert } from "pvtsutils";
import { Any } from "asn1js";

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
      const keys = generateKeyPair(new Uint8Array(Convert.FromBase64Url(json.d)));
      const pubBigNum: EllipticJS.BN = {
        toBytes: () => { return keys.public },
        toArray: () => { return Array.from(keys.public) }
      }
      pubBigNum.toBytes = function () {
        return keys.public
      };

      type Point = any;

      const blankBN = {
        toBytes: () => { return new Uint8Array() },
        toArray: () => { return [] }
      };

      const pF = (enc: any) => {
        if (enc === "hex") {
          return Convert.ToHex(keys.private);
        } else if (enc === "der") {
          return Uint8Array.from(keys.private);
        } else {
          return keys.private;
        }
      };
      this.data = {
        getSecret: pF,
        getPrivate: pF,
        getPublic: (enc?: "hex" | "der"): number[] | string | Point => {
          if (enc === "hex") {
            return Convert.ToHex(keys.public);
          } else if (enc === "der") {
            return Uint8Array.from(keys.public);
          } else {
            return keys.public;
          }
        },
        priv: keys.private,
        pub: {
          x: pubBigNum, y: blankBN
        },
        sign: (data: number[]) => { return false },
        verify: (data: number[], signature: string | object): boolean => { return false },
        derive: (point: any) => { return blankBN }

      };
    }

    return this;
  }

}
