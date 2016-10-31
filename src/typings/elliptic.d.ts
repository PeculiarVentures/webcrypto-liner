declare namespace EllipticJS {
    class EC {
        constructor(namedCurve: string);
        genKeyPair(): EllipticKeyPair;
        keyFromPrivate(hexString: string | number[] | ArrayBuffer): EllipticKeyPair;
        keyFromPublic(hexString: string | number[] | ArrayBuffer, enc?: string): EllipticKeyPair;
    }

    class EllipticKeyPair {
        getPrivate(enc?: string): any;
        getPublic(enc?: string): any;
    }

    class EllipticModule {
        version: string;
        utils: {
            assert: Function;
            toArray: Function;
            zero2: Function;
            toHex: Function;
            encode: Function;
            getNAF: Function;
            getJSF: Function;
            cachedProperty: Function;
            parseBytes: Function;
            intFromLE: Function;
        };
        hmacDRBG: Function;
        curves: {
            PresetCurve: any;
            p192: any;
            p224: any;
            p256: any;
            p384: any;
            p521: any;
            curve25519: any;
            ed25519: any;
            secp256k1: any;
        }
        ec: typeof EC;
        eddsa: any;
    }
}

declare module "elliptic" {

    const version: string;
    const utils: {
        assert: Function;
        toArray: Function;
        zero2: Function;
        toHex: Function;
        encode: Function;
        getNAF: Function;
        getJSF: Function;
        cachedProperty: Function;
        parseBytes: Function;
        intFromLE: Function;
    };
    const hmacDRBG: Function;
    const curves: {
        PresetCurve: any;
        p192: any;
        p224: any;
        p256: any;
        p384: any;
        p521: any;
        curve25519: any;
        ed25519: any;
        secp256k1: any;
    }
    const ec: typeof EllipticJS.EC;
    const eddsa: any;

}