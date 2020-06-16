import { Crypto } from "@peculiar/webcrypto";
import { Crypto as WebCrypto, setCrypto } from "../../src";

const crypto = new Crypto();
const nativeGenerateKey = crypto.subtle.generateKey;
const nativeExportKey = crypto.subtle.exportKey;

// asmCrypto doesn't have key generation function and uses native generateKey with RSA-PSS
crypto.subtle.generateKey = async function (...args: any[]) {
  if (args[0]?.name !== "RSA-PSS") {
    throw new Error("Function is broken for test cases");
  }
  return nativeGenerateKey.apply(this, args);
};

// asmCrypto doesn't have key generation function and uses native exportKey with RSA-PSS
crypto.subtle.exportKey = async function (...args: any[]) {
  if (!(
    (args[0] === "pkcs8"
      || args[0] === "spki")
    && args[1].algorithm.name === "RSA-PSS"
  )) {
    throw new Error("Function is broken for test cases");
  }
  return nativeExportKey.apply(this, args);
};

// break crypto functions
[
  "decrypt", "encrypt",
  "wrapKey", "unwrapKey",
  "sign", "verify",
  "deriveBits", "deriveKey",
  "importKey",
  "digest",
].forEach((o) => {
  crypto.subtle[o] = async () => {
    throw new Error("Function is broken for test cases");
  };
});

// set native crypto
setCrypto(crypto);

global["crypto"] = new WebCrypto();
