var helper;
(function (helper) {
    helper.Browser = {
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
        var userAgent = self.navigator.userAgent;
        var reg;
        if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
            res.name = helper.Browser.Edge;
            res.version = reg[1];
        }
        else if (/msie/i.test(userAgent)) {
            res.name = helper.Browser.IE;
            res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/Trident/i.test(userAgent)) {
            res.name = helper.Browser.IE;
            res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/chrome/i.test(userAgent)) {
            res.name = helper.Browser.Chrome;
            res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/safari/i.test(userAgent)) {
            res.name = helper.Browser.Safari;
            res.version = /([\d\.]+) safari/i.exec(userAgent)[1];
        }
        else if (/firefox/i.test(userAgent)) {
            res.name = helper.Browser.Firefox;
            res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
        }
        return res;
    }
    helper.BrowserInfo = BrowserInfo;
})(helper || (helper = {}));
// var alg = { name: "RSA-PSS", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024, saltLength: 32 };
var alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-1" };
var App = (function () {
    function App() {
    }
    App.generateKey = function () {
        var _this = this;
        return liner.crypto.subtle.generateKey(alg, true, ["sign", "verify"])
            .then(function (keys) {
                _this.keys = keys;
                return keys;
            });
    };
    App.exportKey = function () {
        var _this = this;
        return liner.crypto.subtle.exportKey("jwk", _this.keys.publicKey);
    }
    App.importKey = function (jwk) {
        var _this = this;
        return liner.crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"])
            .then(function (key) {
                if (!_this.keys)
                    _this.keys = {};
                _this.keys.publicKey = key;
            });
    }
    App.sign = function (text) {
        if (!this.keys)
            throw new Error("You must generate CryptoKey first");
        var signature;
        var _this = this;
        return Promise.resolve()
            .then(function () { // Sign
                return liner.crypto.subtle.sign(alg, _this.keys.privateKey, _this.stringToBuffer(text));
            })
            .then(function (sig) { // VErify
                signature = sig;
                return liner.crypto.subtle.verify(alg, _this.keys.publicKey, sig, _this.stringToBuffer(text));
            })
            .then(function (res) {
                if (!res)
                    throw new Error("Wrong signature. Verification is false");
                return signature;
            });
    };
    App.verify = function (signature, text) {
        return liner.crypto.subtle.verify(alg, this.keys.publicKey, App.stringToBuffer(signature), App.stringToBuffer(text));
    }
    App.stringToBuffer = function (text) {
        var res = new Uint8Array(text.length);
        for (var i = 0; i < text.length; i++)
            res[i] = text.charCodeAt(i);
        return res;
    };
    App.buffer2string = function (buffer) {
        var res = "";
        for (var i = 0; i < buffer.length; i++)
            res += String.fromCharCode(buffer[i]);
        return res;
    };
    return App;
}());
var SEED_LEN = 20;
onmessage = function (e) {
    var command = e.data[0];
    var params = e.data.slice(1);
    if (!command)
        throw TypeError("Worker's command cannot be empty");
    switch (command) {
        case "seed":
            if (!(params[0] && params[0].length === SEED_LEN))
                throw new Error("Seed has a wrong length");
            Math.seedrandom(params[0]);
            break;
        case "verify":
            Promise.resolve()
                .then(function () { return App.importKey(params[0]); })
                .then(function () { return App.verify(params[1], params[2]); })
                .then(function (res) {
                    return postMessage(["verify", res]);
                })
                .catch(function (e) {
                    postMessage(["error", { name: "WorkerError", message: e.message, stack: e.stack }]);
                });
            break;
        case "sign":
            var jwk;
            Promise.resolve()
                .then(function () { return App.generateKey(); })
                .then(function () { return App.exportKey(); })
                .then(function (_jwk) {
                    jwk = _jwk;
                    return postMessage(["key", JSON.stringify(jwk)]);
                })
                .then(function () { return App.sign.apply(App, params); })
                .then(function (sig) {
                    return postMessage(["sign", App.buffer2string(new Uint8Array(sig)), JSON.stringify(jwk)]);
                })
                .catch(function (e) {
                    postMessage(["error", { name: "WorkerError", message: e.message, stack: e.stack }]);
                });
            break;
        default:
            throw Error("Unknown worker's command '" + command + "'");
    }
};
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

var PATH = "../../src/";

var _self = self;
if (!(_self.crypto || _self.msCrypto)) {
    console.warn("WebCrypto: !WARNING! Webcrypto unable to get crypto || msCrypto getRandomValues, relying on supplied seed.");
    importScripts(PATH + "seedrandom.js");
    postMessage(["seed", SEED_LEN]);
    _self.crypto = { getRandomValues: getRandomValues };
    Object.freeze(_self.crypto);
}


importScripts("../../../dist/webcrypto-liner.lib.js");
switch (helper.BrowserInfo().name) {
    case helper.Browser.IE:
        importScripts(PATH + "promise.min.js");
    case helper.Browser.Edge:
    case helper.Browser.Safari:
        importScripts(PATH + "asmcrypto.min.js");
        importScripts(PATH + "elliptic.min.js");
}
