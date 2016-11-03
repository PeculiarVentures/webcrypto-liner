"use strict";

describe("Test with Mozilla's vectors", () => {

    context("ECDSA", () => {
        it("generateKey", done => {
            var alg = { name: "ECDSA", namedCurve: "P-256" };
            crypto.subtle.generateKey(alg, false, ["sign", "verify"]).then(x => {
                assert.equal(!!x.publicKey, true);
                assert.equal(x.publicKey.algorithm.name == alg.name, true);
                assert.equal(x.publicKey.algorithm.namedCurve == alg.namedCurve, true);
                assert.equal(x.publicKey.type == "public", true);
                assert.equal(x.publicKey.extractable, true);
                assert.equal(x.publicKey.usages.length == 1, true);
                assert.equal(x.publicKey.usages[0] == "verify", true);
                assert.equal(!!x.privateKey, true);
                assert.equal(x.privateKey.algorithm.name == alg.name, true);
                assert.equal(x.privateKey.algorithm.namedCurve == alg.namedCurve, true);
                assert.equal(x.privateKey.type == "private", true);
                assert.equal(!x.privateKey.extractable, true);
                assert.equal(x.privateKey.usages.length == 1, true);
                assert.equal(x.privateKey.usages[0] == "sign", true);
                done();
            })
                .catch(done);
        });

    });

    it("ECDSA JWK import and verify a known-good signature", done => {
        var alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

        console.log(alg, tv.ecdsa_verify.pub_jwk, tv.ecdsa_verify.sig, tv.ecdsa_verify.data);

        crypto.subtle.importKey("jwk", tv.ecdsa_verify.pub_jwk, alg, true, ["verify"])
            .then(x => crypto.subtle.verify(alg, x, tv.ecdsa_verify.sig, tv.ecdsa_verify.data))
            .then(v => {
                assert.equal(v, true)
                done();
            })
            .catch(done);
    });

});