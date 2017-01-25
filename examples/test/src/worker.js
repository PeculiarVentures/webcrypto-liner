var Browser = {
    IE: "Internet Explorer",
    Safari: "Safari",
    Edge: "Edge",
    Chrome: "Chrome",
    Firefox: "Firefox Mozilla",
};

/**
 * Returns info about browser 
 */
function BrowserInfo() {
    var res = {
        name: "",
        version: ""
    };
    const userAgent = self.navigator.userAgent;

    var reg;
    if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
        res.name = Browser.Edge;
        res.version = reg[1];
    } else if (/msie/i.test(userAgent)) {
        res.name = Browser.IE;
        res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
    } else if (/Trident/i.test(userAgent)) {
        res.name = Browser.IE;
        res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
    } else if (/chrome/i.test(userAgent)) {
        res.name = Browser.Chrome;
        res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
    } else if (/safari/i.test(userAgent)) {
        res.name = Browser.Safari;
        res.version = /([\d\.]+) safari/i.exec(userAgent)[1];
    } else if (/firefox/i.test(userAgent)) {
        res.name = Browser.Firefox;
        res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
    }
    return res;
}

function getRandomArbitrary(min, max) {
    return Math.random() * (max - min) + min;
}

function getRandomValues(buffer) {
    var buf = new Uint8Array(buffer.buffer);
    var i = 0;
    while (i < buf.length) {
        buf[i++] = getRandomArbitrary(0, 255);
    }
    return buffer;
}

var PATH = "./";

if (!(self.crypto || self.msCrypto)) {
    console.warn("WebCrypto: !WARNING! Webcrypto unable to get crypto || msCrypto getRandomValues, relying on supplied seed.");
    importScripts(PATH + "seedrandom.min.js");
    Math.seedrandom("seed");
    self.crypto = { getRandomValues: getRandomValues };
    Object.freeze(self.crypto);
}

importScripts(PATH + "webcrypto-liner.lib.min.js");
switch (BrowserInfo().name) {
    case Browser.IE:
        importScripts(PATH + "promise.min.js");
    case Browser.Edge:
    case Browser.Safari:
        importScripts(PATH + "asmcrypto.min.js");
        importScripts(PATH + "elliptic.min.js");
}

// Test function

var crypto = liner.crypto;
crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
    .then(function (keyPair) {
        return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, new Uint8Array([1, 2, 3, 4, 5]));
    })
    .then(function (signature) {
        console.log("Signature:", new Uint8Array(signature));
        console.log("Success");
    })
    .catch(function (error) {
        console.error(error);
        console.log(error.message);
    });