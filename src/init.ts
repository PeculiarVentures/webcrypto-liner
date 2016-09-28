namespace webcrypto.liner {
    let _w: any = window;

    export const nativeCrypto: NativeCrypto = _w.msCrypto || _w.crypto;
    export const nativeSubtle = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;
}