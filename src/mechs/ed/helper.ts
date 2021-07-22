import * as core from "webcrypto-core";
import { generateKeyPair } from 'curve25519-js';
import { Convert } from "pvtsutils";

const edOIDs: { [key: string]: string } = {
  // Ed448
  [core.asn1.idEd448]: "Ed448",
  "ed448": core.asn1.idEd448,
  // X448
  [core.asn1.idX448]: "X448",
  "x448": core.asn1.idX448,
  // Ed25519
  [core.asn1.idEd25519]: "Ed25519",
  "ed25519": core.asn1.idEd25519,
  // X25519
  [core.asn1.idX25519]: "X25519",
  "x25519": core.asn1.idX25519,
};

export function getNamedCurveByOid(oid: string) {
  const namedCurve = edOIDs[oid];
  if (!namedCurve) {
    throw new core.OperationError(`Cannot convert OID(${oid}) to WebCrypto named curve`);
  }
  return namedCurve;
}

export function getOidByNamedCurve(namedCurve: string) {
  const oid = edOIDs[namedCurve.toLowerCase()];
  if (!oid) {
    throw new core.OperationError(`Cannot convert WebCrypto named curve '${namedCurve}' to OID`);
  }
  return oid;
}

export function generateEllipticKeys(seed?: any, keys?: any) {
  if (seed) {
    keys = generateKeyPair(seed);
  }

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
  return {
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