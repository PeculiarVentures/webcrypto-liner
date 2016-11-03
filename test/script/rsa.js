"use strict";

for (let i = 0; i < REPEAT; i++) {
    describe("RSA crypto", () => {

        const subtle = {
            native: nativeSubtle,
            js: crypto.subtle,
        }
        const cryptoType = ["native", "js"];
        const keys = [];

        ["RSA-PSS", "RSA-OAEP"].forEach(name =>
            [1024].forEach(modulusLength => {
                [new Uint8Array([3]), new Uint8Array([1, 0, 1])].forEach(publicExponent => {
                    ["SHA-1", "SHA-256"].forEach(hash => {
                        keys.push({
                            name: `${name} bits:${modulusLength} exp:${publicExponent[0] === 3 ? "3" : "65537"} hash: ${hash}`,
                            algorithm: { name, modulusLength, publicExponent, hash },
                            usages: name === "RSA-PSS" ? ["sign", "verify"] : ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
                        })
                    })
                })
            }));

        context("generateKey/import/export", done =>
            keys.forEach(key =>
                ["native", "js"].forEach(type =>
                    it(`${key.name} type:${type}`, done => {
                        const revType = type === "native" ? "js" : "native";

                        subtle[type].generateKey(key.algorithm, true, key.usages)
                            .then(k => {
                                if (type === "native")
                                    key[type] = k;

                                let propmises = ["privateKey", "publicKey"].map(keyType => {
                                    return subtle[type].exportKey("jwk", k[keyType])
                                        .then(jwk => {
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

        context("encrypt/decrypt", () =>
            keys.filter(key => key.algorithm.name === "RSA-OAEP").forEach(key =>
                cryptoType.forEach(type => {
                    [null, new Uint8Array([1, 2, 3, 4, 5, 6])].forEach(label =>
                        it(`${key.name} type:${type} label:${label ? label.length : "null"}`, done => {
                            const alg = Object.assign({}, key.algorithm);
                            if (label)
                                alg.label = label;
                            const revType = type === "native" ? "js" : "native";
                            const data = crypto.getRandomValues(new Uint8Array(16));
                            subtle[type].encrypt(alg, key[type].publicKey, data)
                                .then(enc => {
                                    assert.equal(!!enc, true);
                                    return subtle[revType].decrypt(alg, key[revType].privateKey, enc)
                                })
                                .then(dec => {
                                    assert.equal(!!dec, true);
                                    new Uint8Array(dec).forEach((b, i) => assert.equal(b === data[i], true));
                                    done();
                                })
                                .catch(done)
                        })
                    )
                })
            )
        )

        context("wrapKey/unwrapKey", () => {
            const aes = {};
            before(done => {
                let promises = cryptoType.map(type =>
                    subtle[type].generateKey({
                        name: "AES-CBC",
                        length: 128
                    }, true, ["encrypt", "decrypt"])
                        .then(k =>
                            aes[type] = k
                        )
                )
                Promise.all(promises)
                    .then(() => done())
                    .catch(done)
            });

            keys.filter(key => key.algorithm.name === "RSA-OAEP").forEach(key =>
                cryptoType.forEach(type => {
                    [null, new Uint8Array([1, 2, 3, 4, 5, 6])].forEach(label =>
                        it(`${key.name} type:${type} label:${label ? label.length : "null"}`, done => {
                            const alg = Object.assign({}, key.algorithm);
                            if (label)
                                alg.label = label;
                            const revType = type === "native" ? "js" : "native";
                            const data = crypto.getRandomValues(new Uint8Array(16));
                            subtle[type].wrapKey("raw", aes[type], key[type].publicKey, alg)
                                .then(enc => {
                                    assert.equal(!!enc, true);
                                    return subtle[revType].unwrapKey("raw", enc, key[revType].privateKey, alg, aes[type].algorithm, true, aes[type].usages)
                                })
                                .then(dec => {
                                    assert.equal(!!dec, true);
                                    done();
                                })
                                .catch(done)
                        })
                    )
                })
            )
        });

        context("sign/verify", () =>
            keys.filter(key => key.algorithm.name === "RSA-PSS").forEach(key =>
                ["native", "js"].forEach(type =>
                    [16, 32, 64].forEach(saltLength =>
                        it(`${key.name} type:${type} saltLength:${saltLength}`, done => {
                            const revType = type === "native" ? "js" : "native";
                            const data = crypto.getRandomValues(new Uint8Array(16));
                            let alg = { name: key.algorithm.name };
                            if (saltLength)
                                alg.saltLength = saltLength;
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

    });
}