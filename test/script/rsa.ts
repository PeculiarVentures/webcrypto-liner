import { testCrypto, ITestGenerateKeyAction, ITestActions, browser } from "./helper";
import { Convert } from "pvtsutils";
import { Browser } from "../../src/helper";

context("RSA", () => {

  testCrypto(crypto, [
    // RSASSA-PKCS1-v1_5
    {
      name: "RSASSA-PKCS1-v1_5",
      actions: {
        generateKey: (() => {
          const res: ITestGenerateKeyAction[] = [];
          ["SHA-1", "SHA-256"].forEach((hash) =>
            // ["SHA-1", "SHA-256", "SHA-512"].forEach((hash) =>
            // [new Uint8Array([3])].forEach((publicExponent) =>
            [new Uint8Array([3]), new Uint8Array([1, 0, 1])].forEach((publicExponent) =>
              [1024].forEach((modulusLength) => {
                // [1024, 2048].forEach((modulusLength) => {
                res.push({
                  name: `h:${hash} e:${Convert.ToHex(publicExponent)} n:${modulusLength}`,
                  skip: false,
                  algorithm: {
                    name: "RSASSA-PKCS1-v1_5",
                    hash,
                    publicExponent,
                    modulusLength,
                  } as RsaHashedKeyGenParams,
                  extractable: false,
                  keyUsages: ["sign", "verify"],
                } as ITestGenerateKeyAction);
              }),
            ),
          );
          return res;
        })(),
        sign: [
          {
            name: "SHA-256, e:010001, n:2048",
            algorithm: {
              name: "RSASSA-PKCS1-v1_5",
            },
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: Convert.FromBase64("f8OvbYnwX5YPVPjWkOTalYTFJjS1Ks7iNmPdLEby/kK6BEGk5uPvY/ebcok6sTQpQXJXJFJbOcMrZftmJXpm1szcgOdNgVW6FDc3722a9Mzvk/YfvNUCQRNEMON9lYKdpOLSXAFpXR5ovZytbFQ2w2ztpKkJvNY2QZQlizcZKSg="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: {
                  alg: "RS256",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["verify"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                },
                extractable: true,
                keyUsages: ["verify"],
              },
              privateKey: {
                format: "jwk",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
                data: {
                  alg: "RS256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
                  dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                  dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["sign"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                  p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                  q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                  qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                },
                extractable: true,
                keyUsages: ["sign"],
              },
            },
          },
          {
            name: "SHA-1 e:03 n:1024",
            algorithm: {
              name: "RSASSA-PKCS1-v1_5",
            },
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: Convert.FromHex("2f4cab4f67ca544934e462fd324ea0b52f9040f1453c8c425e818411bf54c3c0cd1d7f2a1d04a820ce28fec996b94a0971d481ec8adee2ee0d8b003c2cb75862d7699a73b798d7fab788956ae17388fed764e7a1a944abf9799534b66e830a5c5f4ea7253b937af6b4fcbd11310da3daebf1f3181041bdd550cbe4ea8ff2e1ed"),
            key: {
              publicKey: {
                format: "spki",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as Algorithm,
                data: Convert.FromBase64("MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDL51DUp2Jxqjr18k5mpAvFBzTLtzK4qL6Pq8H4nXU+8gheGYP2+Vi3J+PSLVTIKk7jPNJ2gQtgnA27TNZxYA0QplEyxq0WQwTMp8vz/PAJYjsLNx8O4g433Ve60dUzZWjjbawX8JeggET37m2EoCsgHXJPe3puloMfD0qRR3BoZwIBAw=="),
                extractable: true,
                keyUsages: ["verify"],
              },
              privateKey: {
                format: "pkcs8",
                algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as Algorithm,
                data: Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMvnUNSnYnGqOvXyTmakC8UHNMu3Mriovo+rwfiddT7yCF4Zg/b5WLcn49ItVMgqTuM80naBC2CcDbtM1nFgDRCmUTLGrRZDBMyny/P88AliOws3Hw7iDjfdV7rR1TNlaONtrBfwl6CARPfubYSgKyAdck97em6Wgx8PSpFHcGhnAgEDAoGAIfvizhvlvZxfKP23u8YB9iveIfPdyXF1F/H1qW+Tin2sD67rU9Q5c9v7TbI4zAcNJd94aRWB5W9Xnzd5EuVXgnnU/wz54Bk6zXMLq/L6oouSLzcRVwz0riaXBa007OTejfS+jVhCAlMM4hqYnCxrRr4BBIEi+WidyHKSs8ynSE8CQQD9BRizPsw8eZXDcJz1TVrNYVk4ZGgWfmgGkdyeSh2A5Smdcmvzcm32dNVH9fqL9P33qoJUw+CoSRKuEB/szIjjAkEAzk4fxZMJbypmMhVPVcLfT2yWtFKcfdO67zu8JE2Ih0xmE8Jb65kkl4LWBuPhCbJ5scGyH+S1eodZsco6jrgtrQJBAKiuEHd/MtL7uSz1vfjePIjrkNBC8A7+8ARhPb7cE6tDcROhnUz28/mjONqj/F1N/qUcVuMtQHAwtx61ap3dsJcCQQCJiWqDt1ufcZl2uN+Ogeo08w8i4b2pN9H00n1tiQWviEQNLD1Hu226VzlZ7UCxIaZ2gSFqmHj8WjvL3CcJ0B5zAkEAlmRgnALghAcJ/WfTMphPKJXhY+H+CgkeE3si2ZgPW1YaDAyhp/xdQabkgbFy70Nq32fuJyxDDS4WhF0aOYz6pw=="),
                extractable: true,
                keyUsages: ["sign"],
              },
            },
          },
        ],
        import: [
          { // public key JWK
            name: "public key JWK",
            format: "jwk" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: {
              alg: "RS256",
              e: "AQAB",
              ext: true,
              key_ops: ["verify"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
            },
            extractable: true,
            keyUsages: ["verify"],
          },
          { // public key SPKI
            name: "public key SPKI",
            format: "spki" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: Convert.FromBase64("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+qm93G7JnqspidZOP9nMMEVkAACWl7mGmiJgepraPmQru/xTkRo9jZsuJv2bgHjSP6fcVX3FQIaKmVZ2owkkpP7g+MY7kTdLg32SMWG7nuehhPvPvfTYnSwld6gVtfGWAT7gbnk7GWbnYgPb9El6w/mfNwZOuJDChFusk/k4S3QIDAQAB"),
            extractable: true,
            keyUsages: ["verify"],
          },
          { // private key JWK
            name: "private key JWK",
            format: "jwk" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: {
              alg: "RS256",
              d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
              dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
              dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
              e: "AQAB",
              ext: true,
              key_ops: ["sign"],
              kty: "RSA",
              n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
              p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
              q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
              qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
            },
            extractable: true,
            keyUsages: ["sign"],
          },
          {
            skip: browser.name === Browser.Edge, // Edge returns PKCS8 with KeyUsages extension
            name: "private key pkcs8",
            format: "pkcs8" as KeyFormat,
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as Algorithm,
            data: Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL6qb3cbsmeqymJ1k4/2cwwRWQAAJaXuYaaImB6mto+ZCu7/FORGj2Nmy4m/ZuAeNI/p9xVfcVAhoqZVnajCSSk/uD4xjuRN0uDfZIxYbue56GE+8+99NidLCV3qBW18ZYBPuBueTsZZudiA9v0SXrD+Z83Bk64kMKEW6yT+ThLdAgMBAAECgYACR4hYnLCn059iyPQQKwqaENUHDnlkv/JT6tsitqyFD/fU/qCxz/Qj5JU3Wt3wfPv04n+tNjxlEFng8jIV0+jK+6jlqkd0AcfquIkrEMdY/GET5F41UQ9JOIXWvLwNJ7nMLvD0Eucf9AzxuQ3hw6e+CquDsRusZaiYAYlW+hHA4wJBAOoxbZgSSUBSJUFF12WCILx+9GPWtN6Fiozbhdr3m+WX9PRLSzRPOjaZyJuOtzp6ByT1tJvMBxV2WX3GFUyD0f8CQQDQa20MyXWQjNJXas3MZek5Ly1SqvkvPQS1VnAhv0Yk8yYnQ/eBnzTXMSBlnj56xTtwtR/4FJkQCZ+coDzQbaMjAkEApOolqL7HwnmWLn7GDX8zGkm0Q1IAj+ouBL7ZZbaTm3wETLtwu+dGsQheEdzP/mfL/CTiCAwGuQBcSItimD0DdQJAFTSY59AnkgmB7TsErWNBE3xlVB/pMpE2xWyCBCz96gyDOUOFDz8vlSV+clhjawJeRd1n30nZOPSBtOHozhwZmQJAFByTxX4G2eXkk1xe0IuiEv7I5NS+CnFyp8iB4XLG0rabnfcIZFKpf//X0sNyVOAVo5+jJMuUYjCRTdaXNAWhkg=="),
            extractable: true,
            keyUsages: ["sign"],
          },
          {
            name: "pkcs8 e:03 n:1024",
            skip: browser.name === Browser.Edge,
            format: "pkcs8",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as Algorithm,
            data: Convert.FromBase64("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMvnUNSnYnGqOvXyTmakC8UHNMu3Mriovo+rwfiddT7yCF4Zg/b5WLcn49ItVMgqTuM80naBC2CcDbtM1nFgDRCmUTLGrRZDBMyny/P88AliOws3Hw7iDjfdV7rR1TNlaONtrBfwl6CARPfubYSgKyAdck97em6Wgx8PSpFHcGhnAgEDAoGAIfvizhvlvZxfKP23u8YB9iveIfPdyXF1F/H1qW+Tin2sD67rU9Q5c9v7TbI4zAcNJd94aRWB5W9Xnzd5EuVXgnnU/wz54Bk6zXMLq/L6oouSLzcRVwz0riaXBa007OTejfS+jVhCAlMM4hqYnCxrRr4BBIEi+WidyHKSs8ynSE8CQQD9BRizPsw8eZXDcJz1TVrNYVk4ZGgWfmgGkdyeSh2A5Smdcmvzcm32dNVH9fqL9P33qoJUw+CoSRKuEB/szIjjAkEAzk4fxZMJbypmMhVPVcLfT2yWtFKcfdO67zu8JE2Ih0xmE8Jb65kkl4LWBuPhCbJ5scGyH+S1eodZsco6jrgtrQJBAKiuEHd/MtL7uSz1vfjePIjrkNBC8A7+8ARhPb7cE6tDcROhnUz28/mjONqj/F1N/qUcVuMtQHAwtx61ap3dsJcCQQCJiWqDt1ufcZl2uN+Ogeo08w8i4b2pN9H00n1tiQWviEQNLD1Hu226VzlZ7UCxIaZ2gSFqmHj8WjvL3CcJ0B5zAkEAlmRgnALghAcJ/WfTMphPKJXhY+H+CgkeE3si2ZgPW1YaDAyhp/xdQabkgbFy70Nq32fuJyxDDS4WhF0aOYz6pw=="),
            extractable: true,
            keyUsages: ["sign"],
          },
          {
            name: "spki e:03 n:1024",
            format: "spki",
            algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" } as Algorithm,
            data: Convert.FromBase64("MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDL51DUp2Jxqjr18k5mpAvFBzTLtzK4qL6Pq8H4nXU+8gheGYP2+Vi3J+PSLVTIKk7jPNJ2gQtgnA27TNZxYA0QplEyxq0WQwTMp8vz/PAJYjsLNx8O4g433Ve60dUzZWjjbawX8JeggET37m2EoCsgHXJPe3puloMfD0qRR3BoZwIBAw=="),
            extractable: true,
            keyUsages: ["verify"],
          },
        ],
      },
    },
    // RSA-PSS
    {
      name: "RSA-PSS",
      actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
          return {
            name: hash,
            algorithm: {
              name: "RSA-PSS",
              hash,
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 1024,
            } as RsaHashedKeyGenParams,
            extractable: false,
            keyUsages: ["sign", "verify"],
          } as ITestGenerateKeyAction;
        }),
        sign: [
          {
            algorithm: {
              name: "RSA-PSS",
              saltLength: 64,
            } as RsaPssParams,
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            signature: Convert.FromBase64("OYz/7fv71ELOs5kuz5IiYq1NsXuOazl22xqIFjiY++hYFzJMWaR+ZI0WPoMOifvb1PNKmdQ4dY+QbpYC1vdzlAKfkLe22l5htLyQaXzjD/yeMZYrL0KmrabC9ayL6bxrMW+ccePStkbrF1Jn0LT09l22aX/r1y3SPrl0b+zwo/Q="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-PSS", hash: "SHA-256" },
                data: {
                  alg: "PS256",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["verify"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                },
                extractable: true,
                keyUsages: ["verify"],
              },
              privateKey: {
                format: "jwk",
                algorithm: { name: "RSA-PSS", hash: "SHA-256" },
                data: {
                  alg: "PS256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
                  dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                  dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["sign"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                  p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                  q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                  qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                },
                extractable: true,
                keyUsages: ["sign"],
              },
            },
          },
        ],
      },
    },
    // RSA-OAEP
    {
      name: "RSA-OAEP",
      actions: {
        generateKey: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((hash) => {
          return {
            name: hash,
            algorithm: {
              name: "RSA-OAEP",
              hash,
              publicExponent: new Uint8Array([1, 0, 1]),
              modulusLength: 1024,
            } as RsaHashedKeyGenParams,
            extractable: false,
            keyUsages: ["encrypt", "decrypt"],
          } as ITestGenerateKeyAction;
        }),
        encrypt: [
          {
            name: "with label",
            algorithm: {
              name: "RSA-OAEP",
              label: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            } as RsaOaepParams,
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            encData: Convert.FromBase64("aHu8PBZuctYecfINKgUdB8gBoLyUUFxTZDTzTHUk9KKxtYywYml48HoijBG5DyaIWUUbOIdPgap9C8pFG2iYShQnE9Aj3gzKLHacBbFw1P79+Ei/Tm0j/THiXqCplBZC4dIp4jhTDepmdrlXZcY0slmjG+h8h8TpSmWKP3pEGGk="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                data: {
                  alg: "RSA-OAEP-256",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["encrypt"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                },
                extractable: true,
                keyUsages: ["encrypt"],
              },
              privateKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                data: {
                  alg: "RSA-OAEP-256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
                  dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                  dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["decrypt"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                  p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                  q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                  qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                },
                extractable: true,
                keyUsages: ["decrypt"],
              },
            },
          },
          {
            name: "without label",
            algorithm: {
              name: "RSA-OAEP",
            } as RsaOaepParams,
            data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            encData: Convert.FromBase64("d91eZMLqHTOIGC+GqfSj13x8aQHkTKqxImwmybFFpR/00n5y4e7tL7XX49izZO/wwgCYkDCentX7BGoPhOv/4RhW9vVlfrjFAFdwZFAOFlumt+9jp2QjBDnwxuoCO/IOhjFFf7rq5hTBUB9eoHsSMp42LA6F/Q3IuxFLaejOWGw="),
            key: {
              publicKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                data: {
                  alg: "RSA-OAEP-256",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["encrypt"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                },
                extractable: true,
                keyUsages: ["encrypt"],
              },
              privateKey: {
                format: "jwk",
                algorithm: { name: "RSA-OAEP", hash: "SHA-256" },
                data: {
                  alg: "RSA-OAEP-256",
                  d: "YZzAFCqJ26kElAO92CZEIBmBhw6MN7cjJy8nMgoHzNx9TH4rI_M71Zf6_DqRYIwWPNd7N-X1DSErNB0A6jUNXr42l3ChBsBB31vjHqQKx95-M6iXVgjJFTzxirNjUuCm_skFYIcXS5oEaXjy5XI3dT8KAEf1M2UA6__LwGrAD8E",
                  dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
                  dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
                  e: "AQAB",
                  ext: true,
                  key_ops: ["decrypt"],
                  kty: "RSA",
                  n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
                  p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
                  q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
                  qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
                },
                extractable: true,
                keyUsages: ["decrypt"],
              },
            },
          },
        ],
      },
    },
  ]);

});
