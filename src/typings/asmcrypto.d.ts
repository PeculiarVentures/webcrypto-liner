/**
 * asmcrypto definition https://github.com/vibornoff/asmcrypto.js
 */

 // tslint:disable

declare namespace asmCrypto {

    type RsaKey = Uint8Array[]

    class AES_ECB {
        static encrypt(data: BufferSource, key: BufferSource, padding: boolean): Uint8Array;
        static decrypt(data: BufferSource, key: BufferSource, padding: boolean): Uint8Array;
    }
    class AES_CBC {
        static encrypt(data: BufferSource, key: BufferSource, padding: BufferSource | undefined, iv: BufferSource): Uint8Array;
        static decrypt(data: BufferSource, key: BufferSource, padding: BufferSource | undefined, iv: BufferSource): Uint8Array;
    }
    class AES_GCM {
        static encrypt(data: BufferSource, key: BufferSource, iv: BufferSource, add: BufferSource | undefined, tagLength: number): Uint8Array;
        static decrypt(data: BufferSource, key: BufferSource, iv: BufferSource, add: BufferSource | undefined, tagLength: number): Uint8Array;
    }

    class SHA1 {
        static bytes(data: BufferSource): ArrayBufferView;
    }
    class SHA256 extends SHA1 { }

    class SHA512 extends SHA1 { }

    class RSA {
        static generateKey(modulusBits: number, publicExponent: number): RsaKey;
    }

    class RSA_OAEP_SHA1 {
        static encrypt(data: BufferSource, key: RsaKey, label?: BufferSource): Uint8Array;
        static decrypt(data: BufferSource, key: RsaKey, label?: BufferSource): Uint8Array;
    }

    class RSA_OAEP_SHA256 extends RSA_OAEP_SHA1 { }
    class RSA_OAEP_SHA512 extends RSA_OAEP_SHA1 { }

    class RSA_PKCS1_v1_5_SHA1 {
        static sign(data: BufferSource, key: RsaKey): ArrayBufferView;
        static verify(signature: BufferSource, data: BufferSource, key: RsaKey): boolean;
    }
    class RSA_PKCS1_v1_5_SHA256 extends RSA_PKCS1_v1_5_SHA1 { }
    class RSA_PKCS1_v1_5_SHA512 extends RSA_PKCS1_v1_5_SHA1 { }

    class RSA_PSS_SHA1 {
        static sign(data: BufferSource, key: RsaKey, saltLength?: number): ArrayBufferView;
        static verify(signature: BufferSource, data: BufferSource, key: RsaKey, saltLength?: number): boolean;
    }

    class RSA_PSS_SHA256 extends RSA_PSS_SHA1 { }
    class RSA_PSS_SHA512 extends RSA_PSS_SHA1 { }

    class PBKDF2 {
        static bytes(password: Uint8Array, salt: Uint8Array, iterations: number, dklen: number) : Uint8Array;
        static hex(password: Uint8Array, salt: Uint8Array, iterations: number, dklen: number) : string;
        static base64(password: Uint8Array, salt: Uint8Array, iterations: number, dklen: number) : string;
    }

    class PBKDF2_HMAC_SHA1 extends PBKDF2 {}
    class PBKDF2_HMAC_SHA256 extends PBKDF2 {}
}

declare module "asmcrypto.js" {
    export = asmCrypto;
}

// tslint:enable
