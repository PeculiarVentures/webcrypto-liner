const subtle = crypto.subtle;

function h2a(hex) {
    const res = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i = i + 2) {
        const c = hex.slice(i, i + 2);
        res[i / 2] = parseInt(c, 16);
    }
    return res.buffer;
}

function h2b(hex) {
    const buf = new Uint8Array(h2a(hex));
    //#region Array to binary string
    let binaryString = "";
    const len = buf.length;
    for (let i = 0; i < len; i++) {
        binaryString = binaryString + String.fromCharCode(buf[i]);
    }
    //#endregion
    //#region Binary string to base64
    let b64String = "";
    if (typeof btoa !== "undefined") {
        b64String = btoa(binaryString);
    } else {
        b64String = new Buffer(buf).toString("base64");
    }
    //#endregion
    return b64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
}

const vectors = {
    "SHA-1": [
        {
            m: h2a("ebf748d748ebbca7d29fb473698a6e6b4fb10c865d4af024cc39ae3df3464ba4f1d6d40f32bf9618a91bb5986fa1a2af048a0e14dc51e5267eb05e127d689d0ac6f1a7f156ce066316b971cc7a11d0fd7a2093e27cf2d08727a4e6748cc32fd59c7810c5b9019df21cdcc0bca432c0a3eed0785387508877114359cee4a071cf"),
            d: h2b("b4a57a9bfbf35d0e352f3481523921ad4fb8dd1b40bb059ed5b150812f9dbd33"),
            x: h2b("70da923e655efcc13e08fefe4549a50dfa4078d7e3ac94678a97bd7eb85c3350"),
            y: h2b("d51218a754c00cf928046e37144af9bd61b6f4430cd8455f528aabab17ce3792"),
            s: h2a("2a8d2020b14e5d83ce6dd41733fd7db42b0076211f4321e52203dfb02fbf489b9570682ef8580c4c9d76f48c50a8c888549e00ea87b428add75ffbc614058eb8"),
        },
        {
            m: h2a("0dcb3e96d77ee64e9d0a350d31563d525755fc675f0c833504e83fc69c030181b42fe80c378e86274a93922c570d54a7a358c05755ec3ae91928e02236e81b43e596e4ccbf6a9104889c388072bec4e1faeae11fe4eb24fa4f9573560dcf2e3abc703c526d46d502c7a7222583431cc8178354ae7dbb84e3479917707bce0968"),
            d: h2b("5ac81c3e88a5ee67b14960c065f4ea20479c10bc55ad4dd70f134f1b249099b8"),
            x: h2b("e01e546d8c99e51d6cfafae9c22df4b4123320af8f2b517c194e2000df7c73a8"),
            y: h2b("84f96476d2a7e9a2c1ab27d75df64d3415a9fa013909e4700688edeb4555b328"),
            s: h2a("6a116702f85a9b2056526352ef3f12b70b665ee0c0a66d70e63d0842936c588627670b8730ce89319cf56474dcdce9c3e82fa2a9bdbcf9e0001202bba652ae9e"),
        },
        {
            m: h2a("9408392847e3a387307fbc6789669974fbdaa49b5f2bd5510895105a11dff9c1caab7e327cec80c281e3d9ff13b9e37bbbd2342da7543733bff9aabbfeacc75a40c75a2c5d2b159290428761b64689e5d51224da41da22482c95965422946a644a8becec98f55f1403f23dc794ee889bf02eb7d833f4d465713201e8460a66ce"),
            d: h2b("3b69ee4dcacceeaa6c968598d46c1d0155cefb3d869634b58021380520f0d240"),
            x: h2b("6561ed684fb1eaabab55e75c3db13c1d398e93999d81c0c1d11abc44a56aca05"),
            y: h2b("5b5e6dfe8a23a3cd71c2d8b84d8912e62e01e55b2219fadae3a90575e69f9f73"),
            s: h2a("8a67f3d7cb4bb0d718d1d2c6a2a4669f7378b854df67eac2744353fee62472a7c6a58c91e507dff45711caa8746df93eeedfa490a30488e04d367dde3829fa43"),
        },
    ],
    "SHA-256": [
        {
            m: h2a("5c868fedb8026979ebd26f1ba07c27eedf4ff6d10443505a96ecaf21ba8c4f0937b3cd23ffdc3dd429d4cd1905fb8dbcceeff1350020e18b58d2ba70887baa3a9b783ad30d3fbf210331cdd7df8d77defa398cdacdfc2e359c7ba4cae46bb74401deb417f8b912a1aa966aeeba9c39c7dd22479ae2b30719dca2f2206c5eb4b7"),
            d: h2b("42202a98374f6dca439c0af88140e41f8eced3062682ec7f9fc8ac9ea83c7cb2"),
            x: h2b("131ca4e5811267fa90fc631d6298c2d7a4ecccc45cc60d378e0660b61f82fe8d"),
            y: h2b("cf5acf8ed3e0bbf735308cc415604bd34ab8f7fc8b4a22741117a7fbc72a7949"),
            s: h2a("d89f9586070230bb03e625cca18c89bb3117cd472ff6ee2a50809f0e8903930945972842e92e3a41abeea1089d812eb5343ca8f075ac9c66e13f3db287048638"),
        },
        {
            m: h2a("17cd4a74d724d55355b6fb2b0759ca095298e3fd1856b87ca1cb2df5409058022736d21be071d820b16dfc441be97fbcea5df787edc886e759475469e2128b22f26b82ca993be6695ab190e673285d561d3b6d42fcc1edd6d12db12dcda0823e9d6079e7bc5ff54cd452dad308d52a15ce9c7edd6ef3dad6a27becd8e001e80f"),
            d: h2b("d89996aada18436e87a5feaccf3fece96977cde0b89d44aedd914ee76e94da1c"),
            x: h2b("54ed69e1bbde38e60c7fb764479e0c2db60f2b853a537818c48d03c524e5245e"),
            y: h2b("5099022ebd231b34098761351e9fabe15c84ad44710a1a66ed57174eb021cfd1"),
            s: h2a("40927e35b7b847a198e130312d5d9264325895892d4a9c262c323ecf500a5759b2a9f6e8660e5bc6eb78a81b76c1eb9c56d8d6860eaabfe9cb58a3587594cdfe"),
        },
        {
            m: h2a("18e55ac264031da435b613fc9dc6c4aafc49aae8ddf6f220d523415896ff915fae5c5b2e6aed61d88e5721823f089c46173afc5d9b47fd917834c85284f62dda6ed2d7a6ff10eb553b9312b05dad7decf7f73b69479c02f14ea0a2aa9e05ec07396cd37c28795c90e590631137102315635d702278e352aa41d0826adadff5e1"),
            d: h2b("14c93e4ba36110e6e062c21a648967e6a5da3bc341b3e19d108eaf3be7459cb6"),
            x: h2b("3b7abc1da3dd104beb2e378c484bb23295027a4f039635891a486f7338d10d73"),
            y: h2b("421f2fb7fc03b792d411c391ce888058a15ae7f4ae9a2da72bb5b817785e8271"),
            s: h2a("df8152746377bd5967b9ca0b3048cd29ce12a97603dced5db3f80d44150abd08b1fae910ce6aa7f23829b3fa362c8c66e15c1a39211a0bbd9ce230c1ef9d79ac"),
        }
    ],
    "SHA-512": [
        {
            m: h2a("975ac93690f0f7b9fea8fbd2d8f13fbdfa59e196cbc27795c0a28c7d1bb0636f7f630eca630ef89e901451a17335d9ca2b10b42947e9add0aa0b3e00ab7a4eb64c3c9fdca43ae7ff515ce09e08ba7b0bfed5bde17c4e0f4c84f9037d1da1cd50c546c29aafe79651d2e6a8e956695255d463772bc50dc8c12be8c8a5a7ea5a8a"),
            d: h2b("fc280d9b8f1e9e51566ea4813f48535fdcc84fe988789bc991dd5aea42282f39"),
            x: h2b("55dffb031040816b472348ffc77f0359c2dd5791bdb6925d0c95792b67454a75"),
            y: h2b("ccb56932797a4c72eae2eba99010ce477c26ba0f65a9f3de484a95f7e8aa6218"),
            s: h2a("2a82d76047c17cdc9ca7b467304e3eea8294446d948c6d0c44bf23b9167c17d77aecd4ca2262f8f09b334d21b55835f882810a05ef52d4f6507c36eba72cbfb9"),
        },
        {
            m: h2a("5b8a6a9c878e401fbb13066324d040b4cd21466d334248a9537c22cee41d9307b6000820e1ed44678c9401dbf722caaa62c453afc4e970cb772b688c436f1397c61f402ddd359e8e40551d43ae26d90a996bf7a0aae0878149f21e07f0e8f25ceb88cf5f2dbb9197c6420129e973caecdad9b7fd9974556db402310ea0871149"),
            d: h2b("5246fe281b4aceb74b66fb48dcf1489971e6b98ad242b92b5e2042829cbe359c"),
            x: h2b("c8921271d9380dc4d580bf1a34913e965865310107c4501944ff6b8ec4848a49"),
            y: h2b("583e75db8c93fa90044ab456f127d0043d31cfd0adcb34c52b733fbb00f6f629"),
            s: h2a("91c38ee963e0dd72bd688be55a17cfa66c94e66a3bf92f5dccdee2b6ba86ddfd23b344220f12b9f80e0cc2b814e5af78ddcf7b767171f36fd2eb60a2eafabc47"),
        },
        {
            m: h2a("bb643b8b0e42e21dfe53651b420fc2af8954cbb588ff80d8358a672ddeaaf94e0b09e081f532dd115419406ec598cb6ca896cc208942a5d6c22ae8729b6a6c73d7142e363bd29b7578a44d21847781f1381787a12971f72a78182dad7413363d925f89b00a0c44eff53983cd01ad50ec8e7b1336542cea128258664509c73ea5"),
            d: h2b("ac19fe78ee61d116055a71f567f67767b6cccb52774817d728b440dd39af5232"),
            x: h2b("9ed0a911e63dc4dcc7a27126d7a3d7b7d7f8821bc491fe79d710c381b4e719b2"),
            y: h2b("fc9a1cf569c6d2a6e045f3f7d753ea63360cdae0bb0a1f13044c3c92a999e32a"),
            s: h2a("d60b181450ef7a04a6c94bb6eaf414864f271fb4e8c1ed8a5e77d285d61792cffdc58064546e725145572de5366110da589345301e5ee9c861ee3b879e9ffe49"),
        },
    ],
};

describe("EC secp256k1", () => {
    context("vectors", () => {
        for (i in vectors) {
            context(i, () => {
                const hash = i;
                const tests = vectors[hash];
                let index = 1;
                tests.forEach((test) => {
                    it(`#${index++}`, (done) => {
                        const alg = {
                            name: "ECDSA",
                            namedCurve: "K-256",
                            hash,
                        };
                        const jwkBase = {
                            kty: "EC",
                            crv: "K-256",
                        }
                        const jwkPrv = Object.assign({}, jwkBase, {
                            x: test.x,
                            y: test.y,
                            d: test.d,
                        });
                        const jwkPub = Object.assign({}, jwkBase, {
                            x: test.x,
                            y: test.y,
                        })
                        let privateKey, publicKey;
                        Promise.resolve()
                            .then(() => {
                                return subtle.importKey("jwk", jwkPrv, alg, false, ["sign"])
                                    .then((key) => {
                                        privateKey = key;
                                    })
                            })
                            .then(() => {
                                return subtle.importKey("jwk", jwkPub, alg, true, ["verify"])
                                    .then((key) => {
                                        publicKey = key;
                                    })
                            })
                            .then(() => {
                                return subtle.sign(alg, privateKey, test.m)
                                    .then((signature) => {
                                        return subtle.verify(alg, publicKey, signature, test.m)
                                    })
                                    .then((ok) => {
                                        assert.equal(ok, true, "Native signed data has wrong signature");
                                    })
                            })
                            .then(() => {
                                return subtle.verify(alg, publicKey, test.s, test.m)
                                    .then((ok) => {
                                        assert.equal(ok, true, "Wrong signature for data from test vector");
                                    })
                            })
                            .then(done, done);
                    });
                });
            });
        }
    });

    const alg = {
        name: "ECDSA",
        namedCurve: "K-256",
    };

    context("generate", () => {
        it("unextractable", (done) => {
            Promise.resolve()
                .then(() => {
                    return crypto.subtle.generateKey(alg, false, ["sign", "verify"])
                })
                .then((keys) => {
                    const { privateKey, publicKey } = keys;
                    assert.equal(privateKey.algorithm.name, "ECDSA");
                    assert.equal(privateKey.algorithm.namedCurve, "K-256");
                    assert.equal(privateKey.type, "private");
                    assert.equal(privateKey.extractable, false);
                    assert.equal(privateKey.usages.length, 1);
                    assert.equal(publicKey.algorithm.name, "ECDSA");
                    assert.equal(publicKey.algorithm.namedCurve, "K-256");
                    assert.equal(publicKey.type, "public");
                    assert.equal(publicKey.extractable, true);
                    assert.equal(publicKey.usages.length, 1);
                })
                .then(done, done);
        });
        it("extractable", (done) => {
            Promise.resolve()
                .then(() => {
                    return crypto.subtle.generateKey(alg, true, ["sign", "verify"])
                })
                .then((keys) => {
                    const { privateKey, publicKey } = keys;
                    assert.equal(privateKey.algorithm.name, "ECDSA");
                    assert.equal(privateKey.algorithm.namedCurve, "K-256");
                    assert.equal(privateKey.type, "private");
                    assert.equal(privateKey.extractable, true);
                    assert.equal(privateKey.usages.length, 1);
                    assert.equal(publicKey.algorithm.name, "ECDSA");
                    assert.equal(publicKey.algorithm.namedCurve, "K-256");
                    assert.equal(publicKey.type, "public");
                    assert.equal(publicKey.extractable, true);
                    assert.equal(publicKey.usages.length, 1);
                })
                .then(done, done);
        });
    });

    context("Export/Import", () => {

        it("jwk", (done) => {
            Promise.resolve()
                .then(() => {
                    return crypto.subtle.generateKey(alg, true, ["sign", "verify"])
                        .then((keys) => {
                            return crypto.subtle.exportKey("jwk", keys.privateKey)
                                .then((jwk) => {
                                    return crypto.subtle.importKey("jwk", jwk, alg, false, ["sign"])
                                })
                                .then((key) => {
                                    assert.equal(key.algorithm.name, "ECDSA");
                                    assert.equal(key.algorithm.namedCurve, "K-256");
                                    assert.equal(key.type, "private");
                                    assert.equal(key.extractable, false);
                                    assert.equal(key.usages.length, 1);
                                })
                                .then(() => {
                                    return crypto.subtle.exportKey("jwk", keys.publicKey)
                                        .then((jwk) => {
                                            return crypto.subtle.importKey("jwk", jwk, alg, false, ["sign"])
                                        })
                                        .then((key) => {
                                            assert.equal(key.algorithm.name, "ECDSA");
                                            assert.equal(key.algorithm.namedCurve, "K-256");
                                            assert.equal(key.type, "public");
                                            assert.equal(key.extractable, false);
                                            assert.equal(key.usages.length, 1);
                                        })
                                })
                        })
                })
                .then(done, done);
        });

    });

    context("Sign/Verify", () => {
        ["SHA-1", "SHA-256", "SHA-512"].forEach((hash) => {
            it(hash, (done) => {
                Promise.resolve()
                    .then(() => {
                        const data = crypto.getRandomValues(new Uint8Array(20));
                        const alg2 = Object.assign({}, alg, { hash })
                        return crypto.subtle.generateKey(alg, false, ["sign", "verify"])
                            .then((keys) => {
                                return crypto.subtle.sign(alg2, keys.privateKey, data)
                                    .then((signature) => {
                                        return crypto.subtle.verify(alg2, keys.publicKey, signature, data)
                                    })
                            })
                            .then((ok) => {
                                assert.equal(ok, true);
                            })
                    })
                    .then(done, done);
            });
        });
    });

});