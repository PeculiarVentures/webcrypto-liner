"use strict";

const liner = require("../build");
const assert = require("assert");

describe("Core", () => {

    [8, 16, 20].forEach(size =>
        it(`getRandomValues size:${size}`, () => {
            let initBuf = new Uint8Array(size);
            const buf = self.crypto.getRandomValues(initBuf)
            assert.equal(buf.byteLength, size);
            assert.equal(!!Buffer.compare(new Buffer(initBuf), new Buffer(buf)), true);
        }));

    context("Subtle", () => {
        var subtle = self.crypto.subtle;

        it(`Has object`, () => {
            assert.equal(!!subtle, true);
        });

        ["generateKey", "sign", "verify", "encrypt", "decrypt",
            "wrapKey", "unwrapKey", "exportKey", "importKey", "deriveKey", "deriveBits"].forEach(fn =>
                it(`Has ${fn}`, () => {
                    assert.equal(!!subtle.generateKey, true);
                }));

        context("generateKey", () => {

            // it("RSASSA-PKCS1-v1_5", (done) => {
            //     subtle.generateKey({ name: "RSA-PSS", hash: "SHA-1", modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]) }, true, ["sign", "verify"])
            //         .then(done, done);
            // });

            it("ECDSA", (done) => {
                subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
                    .then((key) => {
                        assert.equal(!!key, true);
                        return subtle.sign({name: "ECDSA", hash: "SHA-1"}, key.privateKey, new Buffer("test"));
                    })
                    .then((sig) => {
                        assert.equal(!!sig, true);
                        return subtle.verify({name: "ECDSA", hash: "SHA-1"}, key.publicKey, sig, new Buffer("test"));
                    })
                    .then((ver) => {
                        assert.equal(ver, true);
                        done();
                    })
                    .catch(done);
            });

        });

    });


});