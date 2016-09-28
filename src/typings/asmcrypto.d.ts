/**
 * aescrypto definition https://github.com/vibornoff/asmcrypto.js
 */

declare namespace asmCrypto {

    type RsaKey = { [key: number]: Uint8Array }

    class AES_CBC {
        static encrypt(data: BufferSource, key: BufferSource, padding: BufferSource | undefined, iv: BufferSource): BufferSource;
        static decrypt(data: BufferSource, key: BufferSource, padding: BufferSource | undefined, iv: BufferSource): BufferSource;
    }
    class AES_GCM {
        static encrypt(data: BufferSource, key: BufferSource, iv: BufferSource, add: BufferSource | undefined, tagLength: number): BufferSource;
        static decrypt(data: BufferSource, key: BufferSource, iv: BufferSource, add: BufferSource | undefined, tagLength: number): BufferSource;
    }

    class SHA1 {
        static bytes(data: BufferSource): ArrayBufferView;
    }
    class SHA256 extends SHA1 { }

    class RSA {
        static generateKey(modulusBits: number, publicExponent: number): RsaKey;
    }

    class RSA_OAEP_SHA1 {
        static encrypt(data: BufferSource, key: RsaKey, label?: BufferSource): BufferSource;
        static decrypt(data: BufferSource, key: RsaKey, label?: BufferSource): BufferSource;
    }


    class RSA_OAEP_SHA256 extends RSA_OAEP_SHA1 { }

    class RSA_PSS_SHA1 {
        static sign(data: BufferSource, key: RsaKey, saltLength?: number): ArrayBufferView;
        static verify(signature: BufferSource, data: BufferSource, key: RsaKey, saltLength?: number): boolean;
    }

    class RSA_PSS_SHA256 extends RSA_PSS_SHA1 {
    }
}