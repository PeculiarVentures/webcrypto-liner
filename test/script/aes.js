"use strict";


describe("AES crypto", () => {

    const subtle = {
        native: nativeSubtle,
        js: crypto.subtle,
    }
    const cryptoType = ["native", "js"];
    const keys = [];


    ["AES-CBC", "AES-GCM"].forEach(name =>
        [128, 256].forEach(length => {
            keys.push({
                algorithm: { name, length },
                usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
            })
        }));

    context("generateKey/import/export", done =>
        keys.forEach(key =>
            ["native", "js"].forEach(type =>
                it(`${key.algorithm.name} length:${key.algorithm.length} type:${type}`, done => {
                    const revType = type === "native" ? "js" : "native";

                    subtle[type].generateKey(key.algorithm, true, key.usages)
                        .then(k => {
                            if (type === "native")
                                key[type] = k;
                            return subtle[type].exportKey("jwk", k)
                        })
                        .then(jwk =>
                            subtle[revType].importKey("jwk", jwk, key.algorithm, true, key.usages)
                        )
                        .then(k => {
                            assert.equal(!!k, true);
                            if (type === "native")
                                key[revType] = k;
                            done();
                        })
                        .catch(done)
                })
            )
        )
    );

    let params = [];
    keys.forEach(key => {

        switch (key.algorithm.name) {
            case "AES-CBC":
                params = [
                    {
                        name: "iv:16",
                        data: { iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) }
                    }
                ]
                break;
            case "AES-GCM":

                [new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])].forEach(iv =>
                    [null, 32, 64, 96, 104, 112, 120, 128].forEach(tagLength =>
                        [null, new Uint8Array([1, 2, 3, 4, 5, 6])].forEach(additionalData => {
                            let alg = {
                                name: `iv:${iv.length} tagLength:${tagLength} ADD:${additionalData ? additionalData.length : "null"}`,
                                data: { iv }
                            }
                            if (additionalData) alg.additionalData = additionalData;
                            if (tagLength) alg.tagLength = tagLength;
                            params.push(alg);
                        })
                    )
                )

                break;
            default:
                throw new Error(`Unsupported algorithm name ${key.algorithm.name}`);
        }
    })

    context("encrypt/decrypt", () =>
        keys.forEach(key =>
            cryptoType.forEach(type => {
                params.forEach(param => {
                    it(`${key.algorithm.name} length:${key.algorithm.length} type:${type} ${param.name}`, done => {
                        const alg = Object.assign({}, key.algorithm, param.data);
                        const revType = type === "native" ? "js" : "native";
                        const data = new Uint8Array(16);
                        subtle[type].encrypt(alg, key[type], data)
                            .then(enc => {
                                assert.equal(!!enc, true);
                                // return subtle[type].decrypt(alg, key[type], enc)
                                return subtle[revType].decrypt(alg, key[revType], enc)
                            })
                            .then(dec => {
                                assert.equal(!!dec, true);
                                new Uint8Array(dec).forEach((b, i) => assert.equal(b === data[i], true));
                                done();
                            })
                            .catch(done)
                    })
                })
            })
        )
    )

    context("wrapKey/unwrapKey", () => {
        const rsa = {};
        before(done => {
            let promises = cryptoType.map(type =>
                subtle[type].generateKey({
                    name: "RSA-PSS",
                    hash: "SHA-1",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([3])
                }, true, ["sign", "verify"])
                    .then(k =>
                        rsa[type] = k.privateKey
                    )
            )
            Promise.all(promises)
                .then(() => done())
                .catch(done)
        })
        keys.forEach(key =>
            cryptoType.forEach(type => {
                params.forEach(param => {
                    it(`${key.algorithm.name} length:${key.algorithm.length} type:${type} ${param.name}`, done => {
                        const alg = Object.assign({}, key.algorithm, param.data);
                        const revType = type === "native" ? "js" : "native";
                        const data = new Uint8Array(16);
                        subtle[type].wrapKey("jwk", rsa[type], key[type], alg)
                            .then(enc => {
                                assert.equal(!!enc, true);
                                return subtle[revType].unwrapKey("jwk", enc, key[revType], alg, rsa[type].algorithm, true, rsa[type].usages)
                            })
                            .then(dec => {
                                assert.equal(!!dec, true);
                                done();
                            })
                            .catch(done)
                    })
                })
            })
        )
    })

});