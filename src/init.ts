let _w: any;
if (typeof self === "undefined") {
    _w = { crypto: { subtle: {} } };
}
else
    _w = self;

export const nativeCrypto: NativeCrypto = _w.msCrypto || _w.crypto;
export const nativeSubtle: NativeSubtleCrypto = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;