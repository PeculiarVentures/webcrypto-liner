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


context("ECDH_ES", () => {

  context("generate/export/import/sign/verify", () => {
    const alg = { name: "ECDH-ES", namedCurve: "x25519" };
    const data = Buffer.from("Some message to sign");
    /*
    it("pkcs8/spki", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);
      const pkcs8 = await liner.subtle.exportKey("pkcs8", linerKeys.privateKey);
      const spki = await liner.subtle.exportKey("spki", linerKeys.publicKey);

      const nodePrivateKey = await crypto.subtle.importKey("pkcs8", pkcs8, alg, true, ["deriveBits"]);
      const nodePublicKey = await crypto.subtle.importKey("spki", spki, alg, true, ["deriveKey"]);
      const linerPrivateKey = await liner.subtle.importKey("pkcs8", pkcs8, alg, true, ["deriveBits"]);
      const linerPublicKey = await liner.subtle.importKey("spki", spki, alg, true, ["deriveKey"]);

      assert.deepStrictEqual(
        await crypto.subtle.exportKey("pkcs8", nodePrivateKey),
        await liner.subtle.exportKey("pkcs8", linerPrivateKey)
      );
      assert.deepStrictEqual(
        await crypto.subtle.exportKey("spki", nodePublicKey),
        await liner.subtle.exportKey("spki", linerPublicKey)
      );

    });

    it("jwk", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);
      const privateJwk = await liner.subtle.exportKey("jwk", linerKeys.privateKey);
      const publicJwk = await liner.subtle.exportKey("jwk", linerKeys.publicKey);

      const nodePrivateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
      const nodePublicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, true, ["deriveKey"]);
      const linerPrivateKey = await liner.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
      const linerPublicKey = await liner.subtle.importKey("jwk", publicJwk, alg, true, ["deriveKey"]);
      assert.deepStrictEqual(
        await crypto.subtle.exportKey("jwk", nodePrivateKey),
        await liner.subtle.exportKey("jwk", linerPrivateKey)
      );
      assert.deepStrictEqual(
        await crypto.subtle.exportKey("jwk", nodePublicKey),
        await liner.subtle.exportKey("jwk", linerPublicKey)
      );

    });

    it("pkcs8/raw", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);
      const pkcs8 = await liner.subtle.exportKey("pkcs8", linerKeys.privateKey);
      const raw = await liner.subtle.exportKey("raw", linerKeys.publicKey);

      const nodePrivateKey = await crypto.subtle.importKey("pkcs8", pkcs8, alg, true, ["deriveBits"]);
      const nodePublicKey = await crypto.subtle.importKey("raw", raw, alg, true, ["deriveKey"]);
      const linerPrivateKey = await liner.subtle.importKey("pkcs8", pkcs8, alg, true, ["deriveBits"]);
      const linerPublicKey = await liner.subtle.importKey("raw", raw, alg, true, ["deriveKey"]);
      assert.deepStrictEqual(
        await crypto.subtle.exportKey("pkcs8", nodePrivateKey),
        await liner.subtle.exportKey("pkcs8", linerPrivateKey)
      );
      assert.deepStrictEqual(
        await crypto.subtle.exportKey("raw", nodePublicKey),
        await liner.subtle.exportKey("raw", linerPublicKey)
      );
    });
    */
    it("deriveBits", async () => {
      const linerKeys = await liner.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"]);

      const privateJwk = {
        kty: "OKP",
        crv: "X25519",
        key_ops: ["deriveBits"],
        ext: true,
        d: "YP_Dbf6rotbZd-2gBwSIdr_MM8ZKiAG33CPvOHo97WI"
        // d(hex): 60ffc36dfeaba2d6d977eda007048876bfcc33c64a8801b7dc23ef387a3ded62
      };

      const publicJwk = {
        kty: "OKP",
        crv: "X25519",
        key_ops: [],
        ext: true,
        x: "4fMe1l0XMe8q8pf3V8Eyz8GSChoLfULmrr0dAHK0uVA"
        // x(hex): e1f31ed65d1731ef2af297f757c132cfc1920a1a0b7d42e6aebd1d0072b4b950
      };

      const nodePrivateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
      const nodePublicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, true, ["deriveKey"]);
      const linerPrivateKey = await liner.subtle.importKey("jwk", privateJwk, alg, true, ["deriveBits"]);
      const linerPublicKey = await liner.subtle.importKey("jwk", publicJwk, alg, true, ["deriveKey"]);

      let pKNode = await crypto.subtle.exportKey("jwk", nodePublicKey);
      let pKLiner = await liner.subtle.exportKey("jwk", linerPublicKey);
      /* console.log(pKLiner);
      / assert.deepStrictEqual(JSON.stringify(pKLiner), false);
       assert.deepStrictEqual(Convert.FromBase64Url(publicJwk.x), false);*/
      assert.deepStrictEqual(
        Buffer.from(Convert.FromBase64Url(pKNode.x)).toString("hex"),
        Buffer.from(Convert.FromBase64Url(pKLiner.x)).toString("hex"));
      assert.deepStrictEqual(
        Buffer.from(await crypto.subtle.deriveBits({ name: "ECDH-ES", public: nodePublicKey }, nodePrivateKey, 256)).toString("hex"),
        Buffer.from(await liner.subtle.deriveBits({ name: "ECDH-ES", public: linerPublicKey }, linerPrivateKey, 256)).toString("hex")
      )
    });
  });



});