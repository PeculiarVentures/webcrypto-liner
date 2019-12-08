import * as assert from "assert";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { testCrypto } from "./utils";

context("DES", () => {

  testCrypto(crypto, [
    {
      name: "DES-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "DES-CBC", length: 64 } as core.DesKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "DES-CBC",
              iv: Convert.FromUtf8String("12345678"),
            } as core.DesParams,
            data: Convert.FromUtf8String("test message"),
            encData: Convert.FromHex("3af3f901ff01fe0102dfbbf37d9bdb94"),
            key: {
              format: "raw" as KeyFormat,
              algorithm: { name: "DES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
              data: Convert.FromUtf8String("12345678"),
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Convert.FromUtf8String("12345678"),
            algorithm: "DES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk" as KeyFormat,
            data: {
              kty: "oct",
              alg: "DES-CBC",
              k: "MTIzNDU2Nzg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "DES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
      },
    },
    {
      name: "DES-EDE3-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "DES-EDE3-CBC", length: 192 } as core.DesKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "DES-EDE3-CBC",
              iv: Convert.FromUtf8String("12345678"),
            } as core.DesParams,
            data: Convert.FromUtf8String("test message"),
            encData: Convert.FromHex("b9ef20e7db926490e4ff8680d99d2141"),
            key: {
              format: "raw" as KeyFormat,
              algorithm: { name: "DES-EDE3-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
              data: Convert.FromUtf8String("1234567890abcdef12345678"),
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Convert.FromUtf8String("1234567890abcdef12345678"),
            algorithm: "DES-EDE3-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "wrong key size",
            error: true,
            format: "raw",
            data: Convert.FromUtf8String("12345678"),
            algorithm: "DES-EDE3-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "3DES-CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "DES-EDE3-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
  ]);

});
