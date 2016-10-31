let _w: any = self;

export const nativeCrypto: NativeCrypto = _w.msCrypto || _w.crypto;
export const nativeSubtle: NativeSubtleCrypto = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;