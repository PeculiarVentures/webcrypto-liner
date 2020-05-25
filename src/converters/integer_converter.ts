import { IAsnConverter } from "@peculiar/asn1-schema";
import * as asn1 from "asn1js";
import { concat } from "../helper";

export const AsnIntegerArrayBufferConverter: IAsnConverter<ArrayBuffer> = {
  fromASN: (value: any) => {
    const valueHex = value.valueBlock.valueHex;
    return !(new Uint8Array(valueHex)[0])
      ? value.valueBlock.valueHex.slice(1)
      : value.valueBlock.valueHex;
  },
  toASN: (value: ArrayBuffer) => {
    const valueHex = new Uint8Array(value)[0] > 127
      ? concat(new Uint8Array([0]), new Uint8Array(value))
      : new Uint8Array(value);
    return new asn1.Integer({ valueHex: new Uint8Array(valueHex).buffer } as any);
  },
};
