namespace webcrypto.liner {
    let _w: any = window;

    export const nativeCrypto: NativeCrypto = _w.crypto || _w.msCrypto;
    export const nativeSubtle = nativeCrypto.subtle || (nativeCrypto as any).webkitSubtle;
}