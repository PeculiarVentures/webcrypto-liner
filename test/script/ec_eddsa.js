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

//Vectors obtained from https://tools.ietf.org/html/rfc8032#page-24
const Ed25519vectors = {
  "Ed25519": [
    {
      //0 byte message
      Message: h2a(""),
      Seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      Pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      Signiture: h2a("   92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    },
    {
      //1 byte message
      Message: h2a("72"),
      Seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      Pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      Signiture: h2a("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    },
    {
      //2 byte message
      Message: h2a("af82"),
      Seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      Pub: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      Signiture: h2a("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    },
    {
      //1023 byte message
      Message: h2a("06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"),
      Seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      Pub: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      Signiture: h2a("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
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
              namedCurve: "Curve25519"
            };
            const jwkBase = {
              kty: "EC",
              crv: "Curve25519"
            };
            const jwkPrv = Object.assign({}, jwkBase, {
              d: test.Seed
            });
            const jwkPub = Object.assign({}, jwkBase, {
              x: test.Pub
            });
            const privateKey = await subtle.importKey("jwk", jwkPrv, false, ["sign"]);
            const publicKey = await subtle.importKey("jwk", jwkPub, true, ["verify"]);
            const signiture = await subtle.sign(alg, privateKey, test.Message);
            assert.equal(signiture, test.Signiture);
            const verify = await subtle.verify(alg, publicKey, test.signiture ,test.Message); 
            assert(verify, true);
          });
        });
      });
    }
  });
});