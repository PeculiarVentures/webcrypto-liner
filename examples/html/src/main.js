var alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
// var alg = { name: "RSA-PSS", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024, saltLength: 32 };
// var alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-1" };

function App() {
}
App.generateKey = function () {
    var _this = this;
    return crypto.subtle.generateKey(alg, true, ["sign", "verify"])
        .then(function (keys) {
            _this.keys = keys;
            return keys;
        });
};
App.exportKey = function () {
    var _this = this;
    return crypto.subtle.exportKey("jwk", _this.keys.privateKey);
}
App.importKey = function (jwk) {
    var _this = this;
    return crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"])
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
            return crypto.subtle.sign(alg, _this.keys.privateKey, _this.stringToBuffer(text));
        })
        .then(function (sig) { // Verify
            signature = sig;
            console.log(new Uint8Array(_this.stringToBuffer(text)));
            console.log(new Uint8Array(signature));
            return crypto.subtle.verify(alg, _this.keys.publicKey, sig, _this.stringToBuffer(text));
        })
        .then(function (res) {
            console.log("Result", res);
            // if (!res)
            //     throw new Error("Wrong signature. Verification is false");
            return signature;
        });
};
App.verify = function (signature, text) {
    return crypto.subtle.verify(alg, this.keys.publicKey, App.stringToBuffer(signature), App.stringToBuffer(text));
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

function sign() {
    var $result = document.getElementById("result");
    var $text = document.getElementById("text");
    var $signedText = document.getElementById("signed_text");
    var $signature = document.getElementById("signature");
    var $jwk = document.getElementById("jwk");

    Promise.resolve()
        .then(function () {
            $result.style.color = "blue";
            $result.textContent = "Loading...";
            return App.generateKey();
        })
        .then(function () {
            return App.exportKey();
        })
        .then(function (jwk) {
            $jwk.value = JSON.stringify(jwk);

            return App.sign($text.value);
        })
        .then(function (signature) {
            $result.style.color = "green";
            var b64Signature = btoa(App.buffer2string(new Uint8Array(signature)));
            $result.textContent = b64Signature
            $signature.value = b64Signature

            $signedText.value = $text.value;
        })
        .catch(function (err) {
            alert(err.message);
            console.error(err);
        });
}

function verify() {
    var $result = document.getElementById("verify_result");
    var $signedText = document.getElementById("signed_text");
    var $signature = document.getElementById("signature");
    var $jwk = document.getElementById("jwk");

    Promise.resolve()
        .then(function () {
            var jwk = JSON.parse($jwk.value);
            return App.importKey(jwk);
        })
        .then(function () {
            var signature = atob($signature.value);
            var text = $signedText.value;
            return App.verify(signature, text);
        })
        .then(function (res) {
            if (!res)
                $result.style.color = "red";
            else
                $result.style.color = "green";
            $result.textContent = res.toString();
        })
        .catch(function (err) {
            alert(err.message);
            console.error(err);
        });
}