/**
 * aescrypto definition https://github.com/vibornoff/asmcrypto.js
 */

declare namespace asmCrypto {

    type RsaKey = { [key: number]: Uint8Array }

    class AES_CBC {
        static encrypt(data: ArrayBufferView, key: ArrayBufferView, padding: ArrayBufferView, iv: ArrayBufferView): ArrayBufferView;
        static decrypt(data: ArrayBufferView, key: ArrayBufferView, padding: ArrayBufferView, iv: ArrayBufferView): ArrayBufferView;
    }
    class AES_GCM {
        static encrypt(data: ArrayBufferView, key: ArrayBufferView, iv: ArrayBufferView, add: ArrayBufferView, tagLength: number): ArrayBufferView;
        static decrypt(data: ArrayBufferView, key: ArrayBufferView, iv: ArrayBufferView, add: ArrayBufferView, tagLength: number): ArrayBufferView;
    }

    class SHA1 {
        static bytes(data: ArrayBufferView): ArrayBufferView;
    }
    class SHA256 {
        static bytes(data: ArrayBufferView): ArrayBufferView;
    }

    class RSA {
        static generateKey(modulusBits: number, publicExponent: number): RsaKey;
    }

    class RSA_OAEP_SHA1 {
        static encrypt(data: ArrayBufferView, key: RsaKey, label?: ArrayBufferView): ArrayBufferView;
        static decrypt(data: ArrayBufferView, key: RsaKey, label?: ArrayBufferView): ArrayBufferView;
    }


    class RSA_OAEP_SHA256 extends RSA_OAEP_SHA1 { }

    class RSA_PSS_SHA1 {
        static sign(data: ArrayBufferView, key: RsaKey, saltLength?: number): ArrayBufferView;
        static verify(signature: ArrayBufferView, data: ArrayBufferView, key: RsaKey, saltLength?: number): boolean;
    }

    class RSA_PSS_SHA256 extends RSA_PSS_SHA1 {
    }
}