"use strict";
for (let i = 0; i < REPEAT; i++) {
    describe("EC crypto", () => {

        const subtle = {
            native: nativeSubtle,
            js: crypto.subtle,
        }
        const cryptoType = ["native", "js"];
        const keys = [];

        ["ECDSA", "ECDH"].forEach(algName => {
            ["P-256", "P-384", "P-521"].forEach(namedCurve => {
                var keyUsage = algName === "ECDSA" ? ["sign", "verify"] : ["deriveKey", "deriveBits"];
                let key = {};
                key.name = `${algName} ${namedCurve}`;
                key.algorithm = { name: algName, namedCurve: namedCurve };
                key.usages = keyUsage;
                keys.push(key);
            });
        });

        context("generateKey/import/export", done =>
            keys.forEach(key =>
                ["native", "js"].forEach(type =>
                    it(`${key.name} type:${type}`, done => {
                        const revType = type === "native" ? "js" : "native";
                        console.log(key.algorithm, true, key.usages)
                        subtle[type].generateKey(key.algorithm, true, key.usages)
                            .then(k => {
                                if (type === "native")
                                    key[type] = k;

                                let propmises = ["privateKey", "publicKey"].map(keyType => {
                                    return subtle[type].exportKey("jwk", k[keyType])
                                        .then(jwk => {
                                            console.log(jwk);
                                            return subtle[revType].importKey("jwk", jwk, key.algorithm, true, jwk.key_ops)
                                        })
                                        .then(k => {
                                            assert.equal(!!k, true);
                                            if (type === "native") {
                                                key[revType] = key[revType] || {};
                                                key[revType][keyType] = k;
                                            }
                                            return Promise.resolve();
                                        })
                                })
                                return Promise.all(propmises);
                            })
                            .then(() =>
                                done()
                            )
                            .catch(done)
                    }).timeout(60e3)
                )
            )
        );

        context("sign/verify", () =>
            keys.filter(key => key.algorithm.name === "ECDSA").forEach(key =>
                ["SHA-1", "SHA-256"].forEach(hash =>
                    ["native", "js"].forEach(type =>
                        it(`${key.name} type:${type} hash:${hash}`, done => {
                            const revType = type === "native" ? "js" : "native";
                            const data = crypto.getRandomValues(new Uint8Array(16));
                            let alg = { name: key.algorithm.name, hash };
                            subtle[type].sign(alg, key[type].privateKey, data)
                                .then(signature => {
                                    assert.equal(!!signature, true);
                                    return subtle[revType].verify(alg, key[revType].publicKey, signature, data);
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
                    it(`${key.name} length:${len}`, done => {
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

    })
}
