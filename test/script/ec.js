"use strict";
describe("EC crypto", () => {

    let keys = []
    let promises = [];
    ["ECDSA", "ECDH"].forEach(algName => {
        ["P-256", "P-384", "P-521"].forEach(namedCurve => {
            var keyUsage = algName === "ECDSA" ? ["sign", "verify"] : ["deriveKey", "deriveBits"];
            let key = {};
            key.algorithm = { name: algName, namedCurve: namedCurve };
            key.usages = keyUsage;
            keys.push(key);
            promises.push(new Promise((resolve, reject) => {
                // Generate native keys
                nativeSubtle.generateKey(key.algorithm, true, keyUsage)
                    .then(keyPair => {
                        key["native"] = keyPair;
                        return nativeSubtle.exportKey("jwk", key.native.privateKey);
                    })
                    .then((privateKey) => {
                        key["privateKey"] = privateKey;
                        return nativeSubtle.exportKey("jwk", key.native.publicKey);
                    })
                    .then((publicKey) => {
                        key["publicKey"] = publicKey;
                        resolve();
                    })
                    .catch(reject);
            }));
        });
    });

    before(done => {
        Promise.all(promises)
            .then(() => done())
            .catch(done);
    });

    context("generateKey", () => {
        keys.forEach(key =>
            it(`${key.algorithm.name} ${key.algorithm.namedCurve}`, done =>
                crypto.subtle.generateKey(key.algorithm, true, key.usages)
                    .then(keyPair =>
                        crypto.subtle.exportKey("jwk", keyPair.privateKey)
                    )
                    .then(jwk =>
                        nativeSubtle.importKey("jwk", jwk, key.algorithm, true, key.usages.filter(usage => usage !== "verify"))
                    )
                    .then(k => {
                        assert(!!k, true);
                        done();
                    })
                    .catch(done)

            )
        )
    });

    context("import", () =>
        keys.forEach(key =>
            ["privateKey", "publicKey"].forEach(type =>
                it(`${key.algorithm.name} ${key.algorithm.namedCurve} ${type}`, done => {
                    let native = key.native[type];
                    crypto.subtle.importKey("jwk", key[type], native.algorithm, native.extractable, native.usages)
                        .then(k => {
                            key.js = key.js || {};
                            key.js[type] = k;
                            done();
                        })
                        .catch(done);
                })
            )
        )
    )

    context("export", () =>
        keys.forEach(key =>
            ["privateKey", "publicKey"].forEach(type =>
                it(`${key.algorithm.name} ${key.algorithm.namedCurve} ${type}`, done => {
                    let native = key.native[type];
                    crypto.subtle.exportKey("jwk", key.js[type])
                        .then(jwk => {
                            assert.equal(jwk.x, key[type].x);
                            assert.equal(jwk.y, key[type].y);
                            if (type === "privateKey")
                                assert.equal(jwk.d, key[type].d);
                            return nativeSubtle.importKey("jwk", jwk, native.algorithm, native.extractable, native.usages)
                        })
                        .then(k => {
                            assert.equal(!!k, true)
                            done();
                        })
                        .catch(done);
                })
            )
        )
    )

    context("sign", () =>
        keys.filter(key => key.algorithm.name === "ECDSA").forEach(key =>
            ["SHA-1", "SHA-256"].forEach(hash =>
                ["native", "js"].forEach(type =>
                    it(`${key.algorithm.name} ${key.algorithm.namedCurve} ${type} ${hash}`, done => {
                        let crypto1 = type === "native" ? nativeSubtle : crypto.subtle;
                        let crypto2 = type === "native" ? crypto.subtle : nativeSubtle;
                        let alg = { name: "ECDSA", hash: hash };
                        let data = new Uint8Array(10);
                        crypto1.sign(alg, key[type].privateKey, data)
                            .then(signature => {
                                assert.equal(!!signature, true);
                                return crypto2.verify(alg, key[type === "native" ? "js" : "native"].publicKey, signature, data);
                            })
                            .then(verify => {
                                assert.equal(verify, true);
                                done();
                            })
                            .catch(done);
                    })
                )
            )
        )
    )

    context("deriveBits", () =>
        keys.filter(key => key.algorithm.name === "ECDH").forEach(key =>
            [128, 192, 256].forEach(len =>
                it(`${key.algorithm.name} ${key.algorithm.namedCurve} length:${len}`, done => {
                    let subtle = {
                        native: nativeSubtle,
                        js: crypto.subtle
                    }
                    let bits = {};
                    const promises = ["native", "js"].map(type =>
                        subtle[type].deriveBits({ name: "ECDH", public: key[type].publicKey }, key[type].privateKey, len)
                            .then(b => {
                                assert.equal(!!b, true);
                                bits[type] = new Uint8Array(b);

                                return Promise.resolve();
                            })
                    )
                    Promise.all(promises)
                        .then(() => {
                            bits["js"].forEach((bit, index) => assert(bits["native"][index] === bit, true, `Bits JS <> Native (${bits["native"][index]} : ${bit})`));
                            done();
                        })
                        .catch(done);
                })
            )
        )
    )

});