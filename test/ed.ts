import * as assert from "assert";
import { Convert } from "pvtsutils";
import { Crypto as NodeCrypto } from "@peculiar/webcrypto";
import { Crypto } from "../src";

const crypto = new NodeCrypto();
const liner = new Crypto();

context("ED", () => {

  context("generate/export/import/sign/verify", () => {
    const alg = { name: "EdDSA", namedCurve: "Ed25519" };
    const data = Buffer.from("Some message to sign");

    it("pkcs8/spki", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["sign", "verify"]);
      const pkcs8 = await liner.subtle.exportKey("pkcs8", linerKeys.privateKey);
      const spki = await liner.subtle.exportKey("spki", linerKeys.publicKey);

      const nodePrivateKey = await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const nodePublicKey = await crypto.subtle.importKey("spki", spki, alg, false, ["verify"]);
      const linerPrivateKey = await liner.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const linerPublicKey = await liner.subtle.importKey("spki", spki, alg, false, ["verify"]);

      const nodeSignature = await crypto.subtle.sign(alg, nodePrivateKey, data);
      const linerSignature = await liner.subtle.sign(alg, linerPrivateKey, data);

      assert.strictEqual(Buffer.from(linerSignature).toString("hex"), Buffer.from(nodeSignature).toString("hex"));

      const nodeOk = await crypto.subtle.verify(alg, nodePublicKey, nodeSignature, data);
      const linerOk = await liner.subtle.verify(alg, linerPublicKey, nodeSignature, data);

      assert.strictEqual(linerOk, nodeOk);
    });

    it("jwk", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["sign", "verify"]);
      const privateJwk = await liner.subtle.exportKey("jwk", linerKeys.privateKey);
      const publicJwk = await liner.subtle.exportKey("jwk", linerKeys.publicKey);

      const nodePrivateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, false, ["sign"]);
      const nodePublicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, false, ["verify"]);
      const linerPrivateKey = await liner.subtle.importKey("jwk", privateJwk, alg, false, ["sign"]);
      const linerPublicKey = await liner.subtle.importKey("jwk", publicJwk, alg, false, ["verify"]);

      const nodeSignature = await crypto.subtle.sign(alg, nodePrivateKey, data);
      const linerSignature = await liner.subtle.sign(alg, linerPrivateKey, data);

      assert.strictEqual(Buffer.from(linerSignature).toString("hex"), Buffer.from(nodeSignature).toString("hex"));

      const nodeOk = await crypto.subtle.verify(alg, nodePublicKey, nodeSignature, data);
      const linerOk = await liner.subtle.verify(alg, linerPublicKey, nodeSignature, data);

      assert.strictEqual(linerOk, nodeOk);
    });

    it("pkcs8/raw", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["sign", "verify"]);
      const pkcs8 = await liner.subtle.exportKey("pkcs8", linerKeys.privateKey);
      const raw = await liner.subtle.exportKey("raw", linerKeys.publicKey);

      const nodePrivateKey = await crypto.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const nodePublicKey = await crypto.subtle.importKey("raw", raw, alg, false, ["verify"]);
      const linerPrivateKey = await liner.subtle.importKey("pkcs8", pkcs8, alg, false, ["sign"]);
      const linerPublicKey = await liner.subtle.importKey("raw", raw, alg, false, ["verify"]);

      const nodeSignature = await crypto.subtle.sign(alg, nodePrivateKey, data);
      const linerSignature = await liner.subtle.sign(alg, linerPrivateKey, data);

      assert.strictEqual(Buffer.from(linerSignature).toString("hex"), Buffer.from(nodeSignature).toString("hex"));

      const nodeOk = await crypto.subtle.verify(alg, nodePublicKey, nodeSignature, data);
      const linerOk = await liner.subtle.verify(alg, linerPublicKey, nodeSignature, data);

      assert.strictEqual(linerOk, nodeOk);
    });

  });



});
