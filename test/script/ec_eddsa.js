if (!h2a) {
  function h2a(hex) {
    const res = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i = i + 2) {
        const c = hex.slice(i, i + 2);
        res[i / 2] = parseInt(c, 16);
    }
    return res.buffer;
  }  
}
//Vectors obtained from https://tools.ietf.org/html/rfc8032#page-24
const Ed25519vectors = {  
  "Ed25519": [
    {
      Message: new TextEncoder("utf-8").encode("eyJhbGciOiJFZDI1NTE5In0.e30"),
      Seed: "VoU6Pm8SOjz8ummuRPsvoJQOPI3cjsdMfUhf2AAEc7s",
      Pub: "l11mBSuP-XxI0KoSG7YEWRp4GWm7dKMOPkItJy2tlMM",
      Signature: h2a("c728362d36e59bbe4a6cb149b5139946112000525d96a1fd6e1c7c6bd2ced72bcbc4d2e13bd7cbaa716e537a2339d6ce6ebf1bb2e6cf90fa947d994f9061d709")
    },
    {
      Message: h2a(""),
      Seed: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=",
      Pub: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
      Signature: h2a("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    },
    {
      Message: h2a("72"),
      Seed: "TM0Imyj_ltqdtsNG7BFOD1uKMZ81q6Yk2oz27U-4pvs=",
      Pub: "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw=",
      Signature: h2a("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    },
    {
      Message: h2a("af82"),
      Seed: "xaqN9D-fg3vtt0QvMdy3sWbThTUHbwlLhc46LgtEWPc=",
      Pub: "_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU=",
      Signature: h2a("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")
    },
    {
      Message: h2a("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"),
      Seed: "9eV2fPFTMZUXYw8iaHa4bIFgzFg7wBN0TGvyVfXMDuU=",
      Pub: "J4EX_BRMcjQPZ9DyMW6Dhs7_vyskKMnFH-98WX8dQm4=",
      Signature: h2a("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03")
    },
    {
      Message: h2a("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
      Seed: "gz_mJAkje51i7HdYdSCRHpp1nOwdGXVbfakBuW3KPUI=",
      Pub: "7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8=",
      Signature: h2a("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")
    },
  ]
};

describe("EC EdDSA", () => {
  describe("vectors", () => {
    for (i in Ed25519vectors) {
      context(i, () => {
        const vectorNum = i;
        const tests = Ed25519vectors[vectorNum];
        let index = 1;
        tests.forEach((test) => {
          it(`#${index++}`, async () => {
            const alg = {
              name: "EdDSA",
              namedCurve: "ED25519",
              hash: "SHA-512"
            };
            const jwkBase = {
              kty: "EC",
              crv: "ED25519"
            };
            const jwkPrv = Object.assign({}, jwkBase, {
              d: test.Seed
            });
            const jwkPub = Object.assign({}, jwkBase, {
              x: test.Pub
            });
            const privateKey = await subtle.importKey("jwk", jwkPrv, alg, false, ["sign"]);
            const publicKey = await subtle.importKey("jwk", jwkPub, alg, true, ["verify"]);
            const signature = await subtle.sign(alg, privateKey, test.Message);
            const sigBuffer = Uint8Array.from(signature);

            assert.equal(util.memcmp(sigBuffer, test.Signature), true);

            const verify = await subtle.verify(alg, publicKey, sigBuffer, test.Message);

            assert(verify, true);
          });
        });
      });
    }
  });
});