var liner =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// identity function for calling harmony imports with the correct context
/******/ 	__webpack_require__.i = function(value) { return value; };
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 15);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
Object.defineProperty(__webpack_exports__, "__esModule", { value: true });
/* WEBPACK VAR INJECTION */(function(global) {/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "WebCryptoError", function() { return WebCryptoError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AlgorithmError", function() { return AlgorithmError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "CryptoKeyError", function() { return CryptoKeyError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "PrepareAlgorithm", function() { return PrepareAlgorithm; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "PrepareData", function() { return PrepareData; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "BaseCrypto", function() { return BaseCrypto; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AlgorithmNames", function() { return AlgorithmNames; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Base64Url", function() { return Base64Url; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "SubtleCrypto", function() { return SubtleCrypto; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Aes", function() { return Aes; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesAlgorithmError", function() { return AesAlgorithmError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesWrapKey", function() { return AesWrapKey; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesEncrypt", function() { return AesEncrypt; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesECB", function() { return AesECB; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesCBC", function() { return AesCBC; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesCTR", function() { return AesCTR; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesGCM", function() { return AesGCM; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "AesKW", function() { return AesKW; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaKeyGenParamsError", function() { return RsaKeyGenParamsError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaHashedImportParamsError", function() { return RsaHashedImportParamsError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Rsa", function() { return Rsa; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaSSA", function() { return RsaSSA; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaPSSParamsError", function() { return RsaPSSParamsError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaPSS", function() { return RsaPSS; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaOAEPParamsError", function() { return RsaOAEPParamsError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "RsaOAEP", function() { return RsaOAEP; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "EcKeyGenParamsError", function() { return EcKeyGenParamsError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Ec", function() { return Ec; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "EcAlgorithmError", function() { return EcAlgorithmError; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "EcDSA", function() { return EcDSA; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "EcDH", function() { return EcDH; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "ShaAlgorithms", function() { return ShaAlgorithms; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Sha", function() { return Sha; });
/* harmony import */ var __WEBPACK_IMPORTED_MODULE_0_tslib__ = __webpack_require__(6);



function printf(text) {
    var args = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        args[_i - 1] = arguments[_i];
    }
    var msg = text;
    var regFind = /[^%](%\d+)/g;
    var match;
    var matches = [];
    while (match = regFind.exec(msg)) {
        matches.push({ arg: match[1], index: match.index });
    }
    for (var i = matches.length - 1; i >= 0; i--) {
        var item = matches[i];
        var arg = item.arg.substring(1);
        var index = item.index + 1;
        msg = msg.substring(0, index) + arguments[+arg] + msg.substring(index + 1 + arg.length);
    }
    msg = msg.replace("%%", "%");
    return msg;
}
var WebCryptoError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(WebCryptoError, _super);
    function WebCryptoError(template) {
        var args = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            args[_i - 1] = arguments[_i];
        }
        var _this = _super.call(this) || this;
        _this.code = 0;
        _this.message = printf.apply(void 0, [template].concat(args));
        var error = new Error(_this.message);
        error.name = _this["constructor"].name;
        _this.stack = error.stack;
        return _this;
    }
    return WebCryptoError;
}(Error));
WebCryptoError.NOT_SUPPORTED = "Method is not supported";
var AlgorithmError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AlgorithmError, _super);
    function AlgorithmError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 1;
        return _this;
    }
    return AlgorithmError;
}(WebCryptoError));
AlgorithmError.PARAM_REQUIRED = "Algorithm hasn't got required paramter '%1'";
AlgorithmError.PARAM_WRONG_TYPE = "Algorithm has got wrong type for paramter '%1'. Must be %2";
AlgorithmError.PARAM_WRONG_VALUE = "Algorithm has got wrong value for paramter '%1'. Must be %2";
AlgorithmError.WRONG_ALG_NAME = "Algorithm has got wrong name '%1'. Must be '%2'";
AlgorithmError.UNSUPPORTED_ALGORITHM = "Algorithm '%1' is not supported";
AlgorithmError.WRONG_USAGE = "Algorithm doesn't support key usage '%1'";
var CryptoKeyError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(CryptoKeyError, _super);
    function CryptoKeyError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 3;
        return _this;
    }
    return CryptoKeyError;
}(WebCryptoError));
CryptoKeyError.EMPTY_KEY = "CryptoKey is empty";
CryptoKeyError.WRONG_KEY_ALG = "CryptoKey has wrong algorithm '%1'. Must be '%2'";
CryptoKeyError.WRONG_KEY_TYPE = "CryptoKey has wrong type '%1'. Must be '%2'";
CryptoKeyError.WRONG_KEY_USAGE = "CryptoKey has wrong key usage. Must be '%1'";
CryptoKeyError.NOT_EXTRACTABLE = "CryptoKey is not extractable";
CryptoKeyError.WRONG_FORMAT = "CryptoKey has '%1' type. It can be used with '%2' format";
CryptoKeyError.UNKNOWN_FORMAT = "Unknown format in use '%1'. Must be one of 'raw', 'pkcs8', 'spki'  or 'jwk'";
CryptoKeyError.ALLOWED_FORMAT = "Wrong format value '%1'. Must be %2";

function PrepareAlgorithm(alg) {
    var res;
    if (typeof alg === "string") {
        res = { name: alg };
    }
    else {
        res = alg;
    }
    BaseCrypto.checkAlgorithm(res);
    var hashedAlg = alg;
    if (hashedAlg.hash) {
        hashedAlg.hash = PrepareAlgorithm(hashedAlg.hash);
    }
    return res;
}
function PrepareData(data, paramName) {
    if (!data) {
        throw new WebCryptoError("Parameter '" + paramName + "' is required and cant be empty");
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(data)) {
        return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer);
    }
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    throw new WebCryptoError("Incoming parameter '" + paramName + "' has wrong data type. Must be ArrayBufferView or ArrayBuffer");
}
var BaseCrypto = (function () {
    function BaseCrypto() {
    }
    BaseCrypto.checkAlgorithm = function (alg) {
        if (typeof alg !== "object") {
            throw new TypeError("Wrong algorithm data type. Must be Object");
        }
        if (!("name" in alg)) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "name");
        }
    };
    BaseCrypto.checkAlgorithmParams = function (alg) {
        this.checkAlgorithm(alg);
    };
    BaseCrypto.checkKey = function (key, alg, type, usage) {
        if (type === void 0) { type = null; }
        if (usage === void 0) { usage = null; }
        if (!key) {
            throw new CryptoKeyError(CryptoKeyError.EMPTY_KEY);
        }
        var keyAlg = key.algorithm;
        this.checkAlgorithm(keyAlg);
        if (alg && (keyAlg.name.toUpperCase() !== alg.toUpperCase())) {
            throw new CryptoKeyError(CryptoKeyError.WRONG_KEY_ALG, keyAlg.name, alg);
        }
        if (type && (!key.type || key.type.toUpperCase() !== type.toUpperCase())) {
            throw new CryptoKeyError(CryptoKeyError.WRONG_KEY_TYPE, key.type, type);
        }
        if (usage) {
            if (!key.usages.some(function (keyUsage) { return usage.toUpperCase() === keyUsage.toUpperCase(); })) {
                throw new CryptoKeyError(CryptoKeyError.WRONG_KEY_USAGE, usage);
            }
        }
    };
    BaseCrypto.checkWrappedKey = function (key) {
        if (!key.extractable) {
            throw new CryptoKeyError(CryptoKeyError.NOT_EXTRACTABLE);
        }
    };
    BaseCrypto.checkKeyUsages = function (keyUsages) {
        if (!keyUsages || !keyUsages.length) {
            throw new WebCryptoError("Parameter 'keyUsages' cannot be empty.");
        }
    };
    BaseCrypto.checkFormat = function (format, type) {
        switch (format.toLowerCase()) {
            case "raw":
                if (type && type.toLowerCase() !== "secret" && type && type.toLowerCase() !== "public") {
                    throw new CryptoKeyError(CryptoKeyError.WRONG_FORMAT, type, "raw");
                }
                break;
            case "pkcs8":
                if (type && type.toLowerCase() !== "private") {
                    throw new CryptoKeyError(CryptoKeyError.WRONG_FORMAT, type, "pkcs8");
                }
                break;
            case "spki":
                if (type && type.toLowerCase() !== "public") {
                    throw new CryptoKeyError(CryptoKeyError.WRONG_FORMAT, type, "spki");
                }
                break;
            case "jwk":
                break;
            default:
                throw new CryptoKeyError(CryptoKeyError.UNKNOWN_FORMAT, format);
        }
    };
    BaseCrypto.generateKey = function (algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.digest = function (algorithm, data) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.sign = function (algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.verify = function (algorithm, key, signature, data) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.encrypt = function (algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.decrypt = function (algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.deriveBits = function (algorithm, baseKey, length) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.exportKey = function (format, key) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    BaseCrypto.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
        });
    };
    return BaseCrypto;
}());

var AlgorithmNames = {
    RsaSSA: "RSASSA-PKCS1-v1_5",
    RsaPSS: "RSA-PSS",
    RsaOAEP: "RSA-OAEP",
    AesECB: "AES-ECB",
    AesCTR: "AES-CTR",
    AesCMAC: "AES-CMAC",
    AesGCM: "AES-GCM",
    AesCBC: "AES-CBC",
    AesKW: "AES-KW",
    Sha1: "SHA-1",
    Sha256: "SHA-256",
    Sha384: "SHA-384",
    Sha512: "SHA-512",
    EcDSA: "ECDSA",
    EcDH: "ECDH",
    Hmac: "HMAC",
    Pbkdf2: "PBKDF2",
};

if (typeof self === "undefined") {
    var g = global;
    g.btoa = function (data) { return new Buffer(data, "binary").toString("base64"); };
    g.atob = function (data) { return new Buffer(data, "base64").toString("binary"); };
}
var Base64Url = (function () {
    function Base64Url() {
    }
    Base64Url.encode = function (value) {
        var str = this.buffer2string(value);
        var res = btoa(str)
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
        return res;
    };
    Base64Url.decode = function (base64url) {
        while (base64url.length % 4) {
            base64url += "=";
        }
        var base64 = base64url
            .replace(/\-/g, "+")
            .replace(/_/g, "/");
        return this.string2buffer(atob(base64));
    };
    Base64Url.buffer2string = function (buffer) {
        var res = "";
        var len = buffer.length;
        for (var i = 0; i < len; i++) {
            res += String.fromCharCode(buffer[i]);
        }
        return res;
    };
    Base64Url.string2buffer = function (binaryString) {
        var res = new Uint8Array(binaryString.length);
        var len = binaryString.length;
        for (var i = 0; i < len; i++) {
            res[i] = binaryString.charCodeAt(i);
        }
        return res;
    };
    return Base64Url;
}());

var AesKeyGenParamsError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesKeyGenParamsError, _super);
    function AesKeyGenParamsError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 7;
        return _this;
    }
    return AesKeyGenParamsError;
}(AlgorithmError));
var Aes = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(Aes, _super);
    function Aes() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Aes.checkKeyUsages = function (keyUsages) {
        var _this = this;
        _super.checkKeyUsages.call(this, keyUsages);
        var wrongUsage = keyUsages.filter(function (usage) { return _this.KEY_USAGES.indexOf(usage) === -1; });
        if (wrongUsage.length) {
            throw new AlgorithmError(AlgorithmError.WRONG_USAGE, wrongUsage.join(", "));
        }
    };
    Aes.checkAlgorithm = function (alg) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    };
    Aes.checkKeyGenParams = function (alg) {
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new AesKeyGenParamsError(AesKeyGenParamsError.PARAM_WRONG_VALUE, "length", "128, 192 or 256");
        }
    };
    Aes.generateKey = function (algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            _this.checkKeyGenParams(algorithm);
            _this.checkKeyUsages(keyUsages);
            resolve(undefined);
        });
    };
    Aes.exportKey = function (format, key) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkKey(key, _this.ALG_NAME);
            _this.checkFormat(format, key.type);
            resolve(undefined);
        });
    };
    Aes.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            _this.checkFormat(format);
            if (!(format.toLowerCase() === "raw" || format.toLowerCase() === "jwk")) {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'jwk' or 'raw'");
            }
            _this.checkKeyUsages(keyUsages);
            resolve(undefined);
        });
    };
    return Aes;
}(BaseCrypto));
Aes.ALG_NAME = "";
Aes.KEY_USAGES = [];
var AesAlgorithmError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesAlgorithmError, _super);
    function AesAlgorithmError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 8;
        return _this;
    }
    return AesAlgorithmError;
}(AlgorithmError));
var AesWrapKey = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesWrapKey, _super);
    function AesWrapKey() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesWrapKey.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(wrapAlgorithm);
            _this.checkKey(wrappingKey, _this.ALG_NAME, "secret", "wrapKey");
            _this.checkWrappedKey(key);
            _this.checkFormat(format, key.type);
            resolve(undefined);
        });
    };
    AesWrapKey.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(unwrapAlgorithm);
            _this.checkKey(unwrappingKey, _this.ALG_NAME, "secret", "unwrapKey");
            _this.checkFormat(format);
            resolve(undefined);
        });
    };
    return AesWrapKey;
}(Aes));
var AesEncrypt = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesEncrypt, _super);
    function AesEncrypt() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesEncrypt.encrypt = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "secret", "encrypt");
            resolve(undefined);
        });
    };
    AesEncrypt.decrypt = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "secret", "decrypt");
            resolve(undefined);
        });
    };
    return AesEncrypt;
}(AesWrapKey));
AesEncrypt.KEY_USAGES = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
var AesECB = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesECB, _super);
    function AesECB() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return AesECB;
}(AesEncrypt));
AesECB.ALG_NAME = AlgorithmNames.AesECB;
var AesCBC = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesCBC, _super);
    function AesCBC() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesCBC.checkAlgorithmParams = function (alg) {
        this.checkAlgorithm(alg);
        if (!alg.iv) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_REQUIRED, "iv");
        }
        if (!(ArrayBuffer.isView(alg.iv) || alg.iv instanceof ArrayBuffer)) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView or ArrayBuffer");
        }
        if (alg.iv.byteLength !== 16) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "iv", "ArrayBufferView or ArrayBuffer with size 16");
        }
    };
    return AesCBC;
}(AesEncrypt));
AesCBC.ALG_NAME = AlgorithmNames.AesCBC;
var AesCTR = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesCTR, _super);
    function AesCTR() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesCTR.checkAlgorithmParams = function (alg) {
        this.checkAlgorithm(alg);
        if (!(alg.counter && (ArrayBuffer.isView(alg.counter) || alg.counter instanceof ArrayBuffer))) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "counter", "ArrayBufferView or ArrayBuffer");
        }
        if (alg.counter.byteLength !== 16) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "counter", "ArrayBufferView or ArrayBuffer with size 16");
        }
        if (!(alg.length > 0 && alg.length <= 128)) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "length", "number [1-128]");
        }
    };
    return AesCTR;
}(AesEncrypt));
AesCTR.ALG_NAME = AlgorithmNames.AesCTR;
var AesGCM = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesGCM, _super);
    function AesGCM() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesGCM.checkAlgorithmParams = function (alg) {
        this.checkAlgorithm(alg);
        if (alg.additionalData) {
            if (!(ArrayBuffer.isView(alg.additionalData) || alg.additionalData instanceof ArrayBuffer)) {
                throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "additionalData", "ArrayBufferView or ArrayBuffer");
            }
        }
        if (!alg.iv) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_REQUIRED, "iv");
        }
        if (!(ArrayBuffer.isView(alg.iv) || alg.iv instanceof ArrayBuffer)) {
            throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_TYPE, "iv", "ArrayBufferView or ArrayBuffer");
        }
        if (alg.tagLength) {
            var ok = [32, 64, 96, 104, 112, 120, 128].some(function (tagLength) {
                return tagLength === alg.tagLength;
            });
            if (!ok) {
                throw new AesAlgorithmError(AesAlgorithmError.PARAM_WRONG_VALUE, "tagLength", "32, 64, 96, 104, 112, 120 or 128");
            }
        }
    };
    return AesGCM;
}(AesEncrypt));
AesGCM.ALG_NAME = AlgorithmNames.AesGCM;
var AesKW = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(AesKW, _super);
    function AesKW() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesKW.checkAlgorithmParams = function (alg) {
        this.checkAlgorithm(alg);
    };
    return AesKW;
}(AesWrapKey));
AesKW.ALG_NAME = AlgorithmNames.AesKW;
AesKW.KEY_USAGES = ["wrapKey", "unwrapKey"];

var ShaAlgorithms = [AlgorithmNames.Sha1, AlgorithmNames.Sha256, AlgorithmNames.Sha384, AlgorithmNames.Sha512].join(" | ");
var Sha = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(Sha, _super);
    function Sha() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Sha.checkAlgorithm = function (alg) {
        var _alg;
        if (typeof alg === "string")
            _alg = { name: alg };
        else
            _alg = alg;
        _super.checkAlgorithm.call(this, _alg);
        switch (_alg.name.toUpperCase()) {
            case AlgorithmNames.Sha1:
            case AlgorithmNames.Sha256:
            case AlgorithmNames.Sha384:
            case AlgorithmNames.Sha512:
                break;
            default:
                throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, _alg.name, ShaAlgorithms);
        }
    };
    Sha.digest = function (algorithm, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            resolve(undefined);
        });
    };
    return Sha;
}(BaseCrypto));

var EcKeyGenParamsError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(EcKeyGenParamsError, _super);
    function EcKeyGenParamsError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 9;
        return _this;
    }
    return EcKeyGenParamsError;
}(AlgorithmError));
var Ec = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(Ec, _super);
    function Ec() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Ec.checkAlgorithm = function (alg) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    };
    Ec.checkKeyGenParams = function (alg) {
        var paramNamedCurve = "namedCurve";
        if (!alg.namedCurve) {
            throw new EcKeyGenParamsError(EcKeyGenParamsError.PARAM_REQUIRED, paramNamedCurve);
        }
        if (!(typeof alg.namedCurve === "string")) {
            throw new EcKeyGenParamsError(EcKeyGenParamsError.PARAM_WRONG_TYPE, paramNamedCurve, "string");
        }
        switch (alg.namedCurve.toUpperCase()) {
            case "P-256":
            case "P-384":
            case "P-521":
                break;
            default:
                throw new EcKeyGenParamsError(EcKeyGenParamsError.PARAM_WRONG_VALUE, paramNamedCurve, "P-256, P-384 or P-521");
        }
    };
    Ec.checkKeyGenUsages = function (keyUsages) {
        var _this = this;
        keyUsages.forEach(function (usage) {
            var i = 0;
            for (i; i < _this.KEY_USAGES.length; i++) {
                if (_this.KEY_USAGES[i].toLowerCase() === usage.toLowerCase()) {
                    break;
                }
            }
            if (i === _this.KEY_USAGES.length) {
                throw new WebCryptoError("Unsupported key usage '" + usage + "'. Should be one of [" + _this.KEY_USAGES.join(", ") + "]");
            }
        });
    };
    Ec.generateKey = function (algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            _this.checkKeyGenParams(algorithm);
            _this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    };
    Ec.exportKey = function (format, key) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkKey(key, _this.ALG_NAME);
            if (!(format && format.toLowerCase() === "raw" && key.type === "public")) {
                _this.checkFormat(format, key.type);
            }
            resolve(undefined);
        });
    };
    Ec.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkKeyGenParams(algorithm);
            _this.checkFormat(format);
            _this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    };
    return Ec;
}(BaseCrypto));
Ec.ALG_NAME = "";
Ec.KEY_USAGES = [];
var EcAlgorithmError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(EcAlgorithmError, _super);
    function EcAlgorithmError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 10;
        return _this;
    }
    return EcAlgorithmError;
}(AlgorithmError));
var EcDSA = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(EcDSA, _super);
    function EcDSA() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcDSA.checkAlgorithmParams = function (alg) {
        this.checkAlgorithm(alg);
        Sha.checkAlgorithm(alg.hash);
    };
    EcDSA.sign = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "private", "sign");
            resolve(undefined);
        });
    };
    EcDSA.verify = function (algorithm, key, signature, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "public", "verify");
            resolve(undefined);
        });
    };
    return EcDSA;
}(Ec));
EcDSA.ALG_NAME = AlgorithmNames.EcDSA;
EcDSA.KEY_USAGES = ["sign", "verify", "deriveKey", "deriveBits"];
var EcDH = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(EcDH, _super);
    function EcDH() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcDH.checkDeriveParams = function (algorithm) {
        var paramPublic = "public";
        this.checkAlgorithm(algorithm);
        if (!algorithm.public) {
            throw new EcAlgorithmError(EcAlgorithmError.PARAM_REQUIRED, paramPublic);
        }
        this.checkKey(algorithm.public, this.ALG_NAME, "public");
    };
    EcDH.deriveBits = function (algorithm, baseKey, length) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkDeriveParams(algorithm);
            _this.checkKey(baseKey, _this.ALG_NAME, "private", "deriveBits");
            resolve(undefined);
        });
    };
    EcDH.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkDeriveParams(algorithm);
            _this.checkKey(baseKey, _this.ALG_NAME, "private", "deriveKey");
            BaseCrypto.checkAlgorithm(derivedKeyType);
            switch (derivedKeyType.name.toUpperCase()) {
                case AlgorithmNames.AesCBC:
                    AesCBC.checkKeyGenParams(derivedKeyType);
                    break;
                case AlgorithmNames.AesCTR:
                    AesCTR.checkKeyGenParams(derivedKeyType);
                    break;
                case AlgorithmNames.AesGCM:
                    AesGCM.checkKeyGenParams(derivedKeyType);
                    break;
                case AlgorithmNames.AesKW:
                    AesKW.checkKeyGenParams(derivedKeyType);
                    break;
                default:
                    throw new EcAlgorithmError("Unsupported name '" + derivedKeyType.name + "' for algorithm in param 'derivedKeyType'");
            }
            resolve(undefined);
        });
    };
    return EcDH;
}(Ec));
EcDH.ALG_NAME = AlgorithmNames.EcDH;
EcDH.KEY_USAGES = ["deriveKey", "deriveBits"];

var Hmac = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(Hmac, _super);
    function Hmac() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Hmac.checkAlgorithm = function (alg) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    };
    Hmac.checkKeyGenParams = function (alg) {
        if ("length" in alg && !(alg.length > 0 && alg.length <= 512)) {
            throw new AlgorithmError(AlgorithmError.PARAM_WRONG_VALUE, "length", "more 0 and less than 512");
        }
    };
    Hmac.checkKeyGenUsages = function (keyUsages) {
        var _this = this;
        this.checkKeyUsages(keyUsages);
        keyUsages.forEach(function (usage) {
            var i = 0;
            for (i; i < _this.KEY_USAGES.length; i++) {
                if (_this.KEY_USAGES[i].toLowerCase() === usage.toLowerCase()) {
                    break;
                }
            }
            if (i === _this.KEY_USAGES.length) {
                throw new WebCryptoError("Unsupported key usage '" + usage + "'. Should be one of [" + _this.KEY_USAGES.join(", ") + "]");
            }
        });
    };
    Hmac.generateKey = function (algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            _this.checkKeyGenParams(algorithm);
            _this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    };
    Hmac.exportKey = function (format, key) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkKey(key, _this.ALG_NAME);
            _this.checkFormat(format, key.type);
            resolve(undefined);
        });
    };
    Hmac.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            _this.checkFormat(format);
            if (!(format.toLowerCase() === "raw" || format.toLowerCase() === "jwk")) {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'jwk' or 'raw'");
            }
            _this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    };
    Hmac.sign = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "secret", "sign");
            resolve(undefined);
        });
    };
    Hmac.verify = function (algorithm, key, signature, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "secret", "verify");
            resolve(undefined);
        });
    };
    return Hmac;
}(BaseCrypto));
Hmac.ALG_NAME = AlgorithmNames.Hmac;
Hmac.KEY_USAGES = ["sign", "verify"];

var Pbkdf2 = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(Pbkdf2, _super);
    function Pbkdf2() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Pbkdf2.checkAlgorithm = function (alg) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    };
    Pbkdf2.checkDeriveParams = function (alg) {
        this.checkAlgorithm(alg);
        if (alg.salt) {
            if (!(ArrayBuffer.isView(alg.salt) || alg.salt instanceof ArrayBuffer)) {
                throw new AlgorithmError(AlgorithmError.PARAM_WRONG_TYPE, "salt", "ArrayBuffer or ArrayBufferView");
            }
        }
        else {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "salt");
        }
        if (!alg.iterations) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "iterations");
        }
        if (!alg.hash) {
            throw new AlgorithmError(AlgorithmError.PARAM_REQUIRED, "hash");
        }
        var hash = PrepareAlgorithm(alg.hash);
        Sha.checkAlgorithm(hash);
    };
    Pbkdf2.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            if (extractable) {
                throw new WebCryptoError("KDF keys must set extractable=false");
            }
            _this.checkAlgorithm(algorithm);
            _this.checkFormat(format);
            if (format.toLowerCase() !== "raw") {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'raw'");
            }
            _this.checkKeyUsages(keyUsages);
        });
    };
    Pbkdf2.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            _this.checkDeriveParams(algorithm);
            _this.checkKey(baseKey, _this.ALG_NAME, "secret", "deriveKey");
            BaseCrypto.checkAlgorithm(derivedKeyType);
            switch (derivedKeyType.name.toUpperCase()) {
                case AlgorithmNames.AesCBC:
                    AesCBC.checkKeyGenParams(derivedKeyType);
                    AesCBC.checkKeyUsages(keyUsages);
                    break;
                case AlgorithmNames.AesCTR:
                    AesCTR.checkKeyGenParams(derivedKeyType);
                    AesCTR.checkKeyUsages(keyUsages);
                    break;
                case AlgorithmNames.AesGCM:
                    AesGCM.checkKeyGenParams(derivedKeyType);
                    AesGCM.checkKeyUsages(keyUsages);
                    break;
                case AlgorithmNames.AesKW:
                    AesKW.checkKeyGenParams(derivedKeyType);
                    AesKW.checkKeyUsages(keyUsages);
                    break;
                case AlgorithmNames.Hmac:
                    Hmac.checkKeyGenParams(derivedKeyType);
                    Hmac.checkKeyUsages(keyUsages);
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, derivedKeyType);
            }
        });
    };
    Pbkdf2.deriveBits = function (algorithm, baseKey, length) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            _this.checkDeriveParams(algorithm);
            _this.checkKey(baseKey, _this.ALG_NAME, "secret", "deriveBits");
            if (!(length && typeof length === "number")) {
                throw new WebCryptoError("Parameter 'length' must be Number and more than 0");
            }
        });
    };
    return Pbkdf2;
}(BaseCrypto));
Pbkdf2.ALG_NAME = AlgorithmNames.Pbkdf2;
Pbkdf2.KEY_USAGES = ["deriveKey", "deriveBits"];

var RsaKeyGenParamsError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaKeyGenParamsError, _super);
    function RsaKeyGenParamsError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 2;
        return _this;
    }
    return RsaKeyGenParamsError;
}(AlgorithmError));
var RsaHashedImportParamsError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaHashedImportParamsError, _super);
    function RsaHashedImportParamsError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 6;
        return _this;
    }
    return RsaHashedImportParamsError;
}(AlgorithmError));
var Rsa = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(Rsa, _super);
    function Rsa() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    Rsa.checkAlgorithm = function (alg) {
        if (alg.name.toUpperCase() !== this.ALG_NAME.toUpperCase()) {
            throw new AlgorithmError(AlgorithmError.WRONG_ALG_NAME, alg.name, this.ALG_NAME);
        }
    };
    Rsa.checkImportAlgorithm = function (alg) {
        this.checkAlgorithm(alg);
        if (!alg.hash) {
            throw new RsaHashedImportParamsError(RsaHashedImportParamsError.PARAM_REQUIRED, "hash");
        }
        Sha.checkAlgorithm(alg.hash);
    };
    Rsa.checkKeyGenParams = function (alg) {
        var modulusBits = alg.modulusLength;
        if (!(modulusBits >= 256 && modulusBits <= 16384 && !(modulusBits % 8))) {
            throw new RsaKeyGenParamsError(RsaKeyGenParamsError.PARAM_WRONG_VALUE, "modulusLength", " a multiple of 8 bits and >= 256 and <= 16384");
        }
        var pubExp = alg.publicExponent;
        if (!pubExp) {
            throw new RsaKeyGenParamsError(RsaKeyGenParamsError.PARAM_REQUIRED, "publicExponent");
        }
        if (!ArrayBuffer.isView(pubExp)) {
            throw new RsaKeyGenParamsError(RsaKeyGenParamsError.PARAM_WRONG_TYPE, "publicExponent", "ArrayBufferView");
        }
        if (!(pubExp[0] === 3 || (pubExp[0] === 1 && pubExp[1] === 0 && pubExp[2] === 1))) {
            throw new RsaKeyGenParamsError(RsaKeyGenParamsError.PARAM_WRONG_VALUE, "publicExponent", "Uint8Array([3]) | Uint8Array([1, 0, 1])");
        }
        if (!alg.hash) {
            throw new RsaKeyGenParamsError(RsaKeyGenParamsError.PARAM_REQUIRED, "hash", ShaAlgorithms);
        }
        Sha.checkAlgorithm(alg.hash);
    };
    Rsa.checkKeyGenUsages = function (keyUsages) {
        var _this = this;
        this.checkKeyUsages(keyUsages);
        keyUsages.forEach(function (usage) {
            var i = 0;
            for (i; i < _this.KEY_USAGES.length; i++) {
                if (_this.KEY_USAGES[i].toLowerCase() === usage.toLowerCase()) {
                    break;
                }
            }
            if (i === _this.KEY_USAGES.length) {
                throw new WebCryptoError("Unsupported key usage '" + usage + "'. Should be one of [" + _this.KEY_USAGES.join(", ") + "]");
            }
        });
    };
    Rsa.generateKey = function (algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithm(algorithm);
            _this.checkKeyGenParams(algorithm);
            _this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    };
    Rsa.exportKey = function (format, key) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkKey(key, _this.ALG_NAME);
            _this.checkFormat(format, key.type);
            resolve(undefined);
        });
    };
    Rsa.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkImportAlgorithm(algorithm);
            _this.checkFormat(format);
            if (format.toLowerCase() === "raw") {
                throw new CryptoKeyError(CryptoKeyError.ALLOWED_FORMAT, format, "'JsonWebKey', 'pkcs8' or 'spki'");
            }
            _this.checkKeyGenUsages(keyUsages);
            resolve(undefined);
        });
    };
    return Rsa;
}(BaseCrypto));
Rsa.ALG_NAME = "";
Rsa.KEY_USAGES = [];
var RsaSSA = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaSSA, _super);
    function RsaSSA() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaSSA.sign = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "private", "sign");
            resolve(undefined);
        });
    };
    RsaSSA.verify = function (algorithm, key, signature, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "public", "verify");
            resolve(undefined);
        });
    };
    return RsaSSA;
}(Rsa));
RsaSSA.ALG_NAME = AlgorithmNames.RsaSSA;
RsaSSA.KEY_USAGES = ["sign", "verify"];
var RsaPSSParamsError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaPSSParamsError, _super);
    function RsaPSSParamsError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 4;
        return _this;
    }
    return RsaPSSParamsError;
}(AlgorithmError));
var RsaPSS = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaPSS, _super);
    function RsaPSS() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaPSS.checkAlgorithmParams = function (algorithm) {
        var alg = algorithm;
        _super.checkAlgorithmParams.call(this, alg);
        if (!alg.saltLength) {
            throw new RsaPSSParamsError(RsaPSSParamsError.PARAM_REQUIRED, "saltLength");
        }
        if (alg.saltLength < 0) {
            throw new RsaPSSParamsError("Parameter 'saltLength' is outside of numeric range");
        }
    };
    return RsaPSS;
}(RsaSSA));
RsaPSS.ALG_NAME = AlgorithmNames.RsaPSS;
var RsaOAEPParamsError = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaOAEPParamsError, _super);
    function RsaOAEPParamsError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 5;
        return _this;
    }
    return RsaOAEPParamsError;
}(AlgorithmError));
var RsaOAEP = (function (_super) {
    __webpack_require__.i(__WEBPACK_IMPORTED_MODULE_0_tslib__["a" /* __extends */])(RsaOAEP, _super);
    function RsaOAEP() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaOAEP.checkAlgorithmParams = function (alg) {
        if (alg.label) {
            if (!(ArrayBuffer.isView(alg.label) || alg.label instanceof ArrayBuffer)) {
                throw new RsaOAEPParamsError(RsaOAEPParamsError.PARAM_WRONG_TYPE, "label", "ArrayBufferView or ArrayBuffer");
            }
        }
    };
    RsaOAEP.encrypt = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "public", "encrypt");
            resolve(undefined);
        });
    };
    RsaOAEP.decrypt = function (algorithm, key, data) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(algorithm);
            _this.checkKey(key, _this.ALG_NAME, "private", "decrypt");
            resolve(undefined);
        });
    };
    RsaOAEP.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(wrapAlgorithm);
            _this.checkKey(wrappingKey, _this.ALG_NAME, "public", "wrapKey");
            _this.checkWrappedKey(key);
            _this.checkFormat(format, key.type);
            resolve(undefined);
        });
    };
    RsaOAEP.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var _this = this;
        return new Promise(function (resolve, reject) {
            _this.checkAlgorithmParams(unwrapAlgorithm);
            _this.checkKey(unwrappingKey, _this.ALG_NAME, "private", "unwrapKey");
            _this.checkFormat(format);
            resolve(undefined);
        });
    };
    return RsaOAEP;
}(Rsa));
RsaOAEP.ALG_NAME = AlgorithmNames.RsaOAEP;
RsaOAEP.KEY_USAGES = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

var SubtleCrypto = (function () {
    function SubtleCrypto() {
    }
    SubtleCrypto.prototype.generateKey = function (algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaSSA.toUpperCase():
                    Class = RsaSSA;
                    break;
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.RsaPSS.toUpperCase():
                    Class = RsaPSS;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.generateKey(alg, extractable, keyUsages).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.digest = function (algorithm, data) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var buf = PrepareData(data, "data");
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.Sha1.toUpperCase():
                case AlgorithmNames.Sha256.toUpperCase():
                case AlgorithmNames.Sha384.toUpperCase():
                case AlgorithmNames.Sha512.toUpperCase():
                    Class = Sha;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.digest(alg, buf).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.sign = function (algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var buf = PrepareData(data, "data");
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaSSA.toUpperCase():
                    Class = RsaSSA;
                    break;
                case AlgorithmNames.RsaPSS.toUpperCase():
                    Class = RsaPSS;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.sign(alg, key, buf).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.verify = function (algorithm, key, signature, data) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var sigBuf = PrepareData(data, "signature");
            var buf = PrepareData(data, "data");
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaSSA.toUpperCase():
                    Class = RsaSSA;
                    break;
                case AlgorithmNames.RsaPSS.toUpperCase():
                    Class = RsaPSS;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.verify(alg, key, sigBuf, buf).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.encrypt = function (algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var buf = PrepareData(data, "data");
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.encrypt(alg, key, buf).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.decrypt = function (algorithm, key, data) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var buf = PrepareData(data, "data");
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.decrypt(alg, key, buf).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.deriveBits = function (algorithm, baseKey, length) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Pbkdf2.toUpperCase():
                    Class = Pbkdf2;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.deriveBits(alg, baseKey, length).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var derivedAlg = PrepareAlgorithm(derivedKeyType);
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Pbkdf2.toUpperCase():
                    Class = Pbkdf2;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.deriveKey(alg, baseKey, derivedAlg, extractable, keyUsages).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.exportKey = function (format, key) {
        return new Promise(function (resolve, reject) {
            BaseCrypto.checkKey(key);
            if (!key.extractable) {
                throw new CryptoKeyError(CryptoKeyError.NOT_EXTRACTABLE);
            }
            var Class = BaseCrypto;
            switch (key.algorithm.name.toUpperCase()) {
                case AlgorithmNames.RsaSSA.toUpperCase():
                    Class = RsaSSA;
                    break;
                case AlgorithmNames.RsaPSS.toUpperCase():
                    Class = RsaPSS;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
            }
            Class.exportKey(format, key).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(algorithm);
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaSSA.toUpperCase():
                    Class = RsaSSA;
                    break;
                case AlgorithmNames.RsaPSS.toUpperCase():
                    Class = RsaPSS;
                    break;
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                case AlgorithmNames.EcDSA.toUpperCase():
                    Class = EcDSA;
                    break;
                case AlgorithmNames.EcDH.toUpperCase():
                    Class = EcDH;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    Class = Hmac;
                    break;
                case AlgorithmNames.Pbkdf2.toUpperCase():
                    Class = Pbkdf2;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.importKey(format, keyData, alg, extractable, keyUsages).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        return new Promise(function (resolve, reject) {
            var alg = PrepareAlgorithm(wrapAlgorithm);
            var Class = BaseCrypto;
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            Class.wrapKey(format, key, wrappingKey, alg).then(resolve, reject);
        });
    };
    SubtleCrypto.prototype.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        return new Promise(function (resolve, reject) {
            var unwrapAlg = PrepareAlgorithm(unwrapAlgorithm);
            var unwrappedAlg = PrepareAlgorithm(unwrappedKeyAlgorithm);
            var buf = PrepareData(wrappedKey, "wrappedKey");
            var Class = BaseCrypto;
            switch (unwrapAlg.name.toUpperCase()) {
                case AlgorithmNames.RsaOAEP.toUpperCase():
                    Class = RsaOAEP;
                    break;
                case AlgorithmNames.AesECB.toUpperCase():
                    Class = AesECB;
                    break;
                case AlgorithmNames.AesCBC.toUpperCase():
                    Class = AesCBC;
                    break;
                case AlgorithmNames.AesCTR.toUpperCase():
                    Class = AesCTR;
                    break;
                case AlgorithmNames.AesGCM.toUpperCase():
                    Class = AesGCM;
                    break;
                case AlgorithmNames.AesKW.toUpperCase():
                    Class = AesKW;
                    break;
                default:
                    throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, unwrapAlg.name);
            }
            Class.unwrapKey(format, buf, unwrappingKey, unwrapAlg, unwrappedAlg, extractable, keyUsages).then(resolve, reject);
        });
    };
    return SubtleCrypto;
}());



/* WEBPACK VAR INJECTION */}.call(__webpack_exports__, __webpack_require__(13)))

/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var webcrypto_core_1 = __webpack_require__(0);
var LinerError = (function (_super) {
    __extends(LinerError, _super);
    function LinerError() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.code = 10;
        return _this;
    }
    return LinerError;
}(webcrypto_core_1.WebCryptoError));
LinerError.MODULE_NOT_FOUND = "Module '%1' is not found. Download it from %2";
LinerError.UNSUPPORTED_ALGORITHM = "Unsupported algorithm '%1'";
exports.LinerError = LinerError;


/***/ }),
/* 2 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
var subtle_1 = __webpack_require__(12);
var init_1 = __webpack_require__(4);
var Crypto = (function () {
    function Crypto() {
        this.subtle = new subtle_1.SubtleCrypto();
    }
    Crypto.prototype.getRandomValues = function (array) {
        return init_1.nativeCrypto.getRandomValues(array);
    };
    return Crypto;
}());
exports.Crypto = Crypto;


/***/ }),
/* 3 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.Browser = {
    IE: "Internet Explorer",
    Safari: "Safari",
    Edge: "Edge",
    Chrome: "Chrome",
    Firefox: "Firefox Mozilla",
    Mobile: "Mobile",
};
/**
 * Returns info about browser
 */
function BrowserInfo() {
    var res = {
        name: "Unknown",
        version: "0",
    };
    var userAgent = self.navigator.userAgent;
    var reg;
    // tslint:disable-next-line:no-conditional-assignment
    if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
        res.name = exports.Browser.Edge;
        res.version = reg[1];
    }
    else if (/msie/i.test(userAgent)) {
        res.name = exports.Browser.IE;
        res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/Trident/i.test(userAgent)) {
        res.name = exports.Browser.IE;
        res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/chrome/i.test(userAgent)) {
        res.name = exports.Browser.Chrome;
        res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/mobile/i.test(userAgent)) {
        res.name = exports.Browser.Mobile;
        res.version = /mobile\/([\w]+)/i.exec(userAgent)[1];
    }
    else if (/safari/i.test(userAgent)) {
        res.name = exports.Browser.Safari;
        res.version = /version\/([\d\.]+)/i.exec(userAgent)[1];
    }
    else if (/firefox/i.test(userAgent)) {
        res.name = exports.Browser.Firefox;
        res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
    }
    return res;
}
exports.BrowserInfo = BrowserInfo;
function string2buffer(binaryString) {
    var res = new Uint8Array(binaryString.length);
    for (var i = 0; i < binaryString.length; i++) {
        res[i] = binaryString.charCodeAt(i);
    }
    return res;
}
exports.string2buffer = string2buffer;
function buffer2string(buffer) {
    var res = "";
    // tslint:disable-next-line:prefer-for-of
    for (var i = 0; i < buffer.length; i++) {
        res += String.fromCharCode(buffer[i]);
    }
    return res;
}
exports.buffer2string = buffer2string;
function concat() {
    var buf = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        buf[_i] = arguments[_i];
    }
    var res = new Uint8Array(buf.map(function (item) { return item.length; }).reduce(function (prev, cur) { return prev + cur; }));
    var offset = 0;
    buf.forEach(function (item, index) {
        for (var i = 0; i < item.length; i++) {
            res[offset + i] = item[i];
        }
        offset += item.length;
    });
    return res;
}
exports.concat = concat;
function assign(target) {
    var sources = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        sources[_i - 1] = arguments[_i];
    }
    var res = arguments[0];
    for (var i = 1; i < arguments.length; i++) {
        var obj = arguments[i];
        for (var prop in obj) {
            res[prop] = obj[prop];
        }
    }
    return res;
}
exports.assign = assign;


/***/ }),
/* 4 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
var error_1 = __webpack_require__(1);
var w;
if (typeof self === "undefined") {
    var crypto_1 = __webpack_require__(14);
    w = {
        crypto: {
            subtle: {},
            getRandomValues: function (array) {
                var buf = array.buffer;
                var uint8buf = new Uint8Array(buf);
                var rnd = crypto_1.randomBytes(uint8buf.length);
                rnd.forEach(function (octet, index) { return uint8buf[index] = octet; });
                return array;
            },
        },
    };
}
else {
    w = self;
}
exports.nativeCrypto = w.msCrypto || w.crypto || {};
exports.nativeSubtle = null;
try {
    exports.nativeSubtle = exports.nativeCrypto.subtle || exports.nativeCrypto.webkitSubtle;
}
catch (err) {
    // Safari throws error on crypto.webkitSubtle in Worker
}
function WrapFunction(subtle, name) {
    var fn = subtle[name];
    // tslint:disable-next-line:only-arrow-functions
    subtle[name] = function () {
        var args = arguments;
        return new Promise(function (resolve, reject) {
            var op = fn.apply(subtle, args);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject("Error on running '" + name + "' function");
            };
        });
    };
}
if (w.msCrypto) {
    if (!w.Promise) {
        throw new error_1.LinerError(error_1.LinerError.MODULE_NOT_FOUND, "Promise", "https://www.promisejs.org");
    }
    WrapFunction(exports.nativeSubtle, "generateKey");
    WrapFunction(exports.nativeSubtle, "digest");
    WrapFunction(exports.nativeSubtle, "sign");
    WrapFunction(exports.nativeSubtle, "verify");
    WrapFunction(exports.nativeSubtle, "encrypt");
    WrapFunction(exports.nativeSubtle, "decrypt");
    WrapFunction(exports.nativeSubtle, "importKey");
    WrapFunction(exports.nativeSubtle, "exportKey");
    WrapFunction(exports.nativeSubtle, "wrapKey");
    WrapFunction(exports.nativeSubtle, "unwrapKey");
    WrapFunction(exports.nativeSubtle, "deriveKey");
    WrapFunction(exports.nativeSubtle, "deriveBits");
}
// fix: Math.imul for IE
if (!Math.imul) {
    // tslint:disable-next-line:only-arrow-functions
    Math.imul = function imul(a, b) {
        var ah = (a >>> 16) & 0xffff;
        var al = a & 0xffff;
        var bh = (b >>> 16) & 0xffff;
        var bl = b & 0xffff;
        return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0) | 0);
    };
}


/***/ }),
/* 5 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
var CryptoKey = (function () {
    function CryptoKey() {
    }
    return CryptoKey;
}());
exports.CryptoKey = CryptoKey;


/***/ }),
/* 6 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
/* harmony export (immutable) */ __webpack_exports__["a"] = __extends;
/* unused harmony export __assign */
/* unused harmony export __rest */
/* unused harmony export __decorate */
/* unused harmony export __param */
/* unused harmony export __metadata */
/* unused harmony export __awaiter */
/* unused harmony export __generator */
/* unused harmony export __exportStar */
/* unused harmony export __values */
/* unused harmony export __read */
/* unused harmony export __spread */
/* unused harmony export __asyncGenerator */
/* unused harmony export __asyncDelegator */
/* unused harmony export __asyncValues */
/*! *****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = Object.setPrototypeOf ||
    ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
    function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = Object.assign || function __assign(t) {
    for (var s, i = 1, n = arguments.length; i < n; i++) {
        s = arguments[i];
        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
    }
    return t;
};

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) if (e.indexOf(p[i]) < 0)
            t[p[i]] = s[p[i]];
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator.throw(value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __exportStar(m, exports) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator], i = 0;
    if (m) return m.call(o);
    return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
};

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), q = [], c, i;
    return i = { next: verb("next"), "throw": verb("throw"), "return": verb("return") }, i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { return function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]), next(); }); }; }
    function next() { if (!c && q.length) resume((c = q.shift())[0], c[1]); }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(c[3], e); } }
    function step(r) { r.done ? settle(c[2], r) : Promise.resolve(r.value[1]).then(r.value[0] === "yield" ? send : fulfill, reject); }
    function send(value) { settle(c[2], { value: value, done: false }); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { c = void 0, f(v), next(); }
};

function __asyncDelegator(o) {
    var i = { next: verb("next"), "throw": verb("throw", function (e) { throw e; }), "return": verb("return", function (v) { return { value: v, done: true }; }) }, p;
    return o = __asyncValues(o), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { return function (v) { return v = p && n === "throw" ? f(v) : p && v.done ? v : { value: p ? ["yield", v.value] : ["await", (o[n] || f).call(o, v)], done: false }, p = !p, v; }; }
};

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator];
    return m ? m.call(o) : typeof __values === "function" ? __values(o) : o[Symbol.iterator]();
};

/***/ }),
/* 7 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

function __export(m) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, "__esModule", { value: true });
__export(__webpack_require__(4));
__export(__webpack_require__(2));


/***/ }),
/* 8 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var webcrypto_core_1 = __webpack_require__(0);
var error_1 = __webpack_require__(1);
var key_1 = __webpack_require__(5);
var helper_1 = __webpack_require__(3);
var init_1 = __webpack_require__(4);
var AesCrypto = (function (_super) {
    __extends(AesCrypto, _super);
    function AesCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    AesCrypto.generateKey = function (alg, extractable, keyUsage) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            _this.checkModule();
            // gat random bytes for key
            var key = init_1.nativeCrypto.getRandomValues(new Uint8Array(alg.length / 8));
            // set key params
            var aesKey = new key_1.CryptoKey();
            aesKey.key = key;
            aesKey.algorithm = alg;
            aesKey.extractable = extractable;
            aesKey.type = "secret";
            aesKey.usages = keyUsage;
            return aesKey;
        });
    };
    AesCrypto.encrypt = function (algorithm, key, data) {
        return Promise.resolve()
            .then(function () {
            var res;
            switch (algorithm.name.toUpperCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB:
                    var algECB = algorithm;
                    res = asmCrypto.AES_ECB.encrypt(data, key.key, true);
                    break;
                case webcrypto_core_1.AlgorithmNames.AesCBC:
                    var algCBC = algorithm;
                    res = asmCrypto.AES_CBC.encrypt(data, key.key, undefined, webcrypto_core_1.PrepareData(algCBC.iv, "iv"));
                    break;
                case webcrypto_core_1.AlgorithmNames.AesGCM:
                    var algGCM = algorithm;
                    algGCM.tagLength = algGCM.tagLength || 128;
                    var additionalData = void 0;
                    if (algGCM.additionalData) {
                        additionalData = webcrypto_core_1.PrepareData(algGCM.additionalData, "additionalData");
                    }
                    res = asmCrypto.AES_GCM.encrypt(data, key.key, algGCM.iv, additionalData, algGCM.tagLength / 8);
                    break;
                default:
                    throw new error_1.LinerError(webcrypto_core_1.AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            return res.buffer;
        });
    };
    AesCrypto.decrypt = function (algorithm, key, data) {
        return Promise.resolve()
            .then(function () {
            var res;
            switch (algorithm.name.toUpperCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB:
                    var algECB = algorithm;
                    res = asmCrypto.AES_ECB.decrypt(data, key.key, true);
                    break;
                case webcrypto_core_1.AlgorithmNames.AesCBC:
                    var algCBC = algorithm;
                    res = asmCrypto.AES_CBC.decrypt(data, key.key, undefined, webcrypto_core_1.PrepareData(algCBC.iv, "iv"));
                    break;
                case webcrypto_core_1.AlgorithmNames.AesGCM:
                    var algGCM = algorithm;
                    algGCM.tagLength = algGCM.tagLength || 128;
                    var additionalData = void 0;
                    if (algGCM.additionalData) {
                        additionalData = webcrypto_core_1.PrepareData(algGCM.additionalData, "additionalData");
                    }
                    res = asmCrypto.AES_GCM.decrypt(data, key.key, algGCM.iv, additionalData, algGCM.tagLength / 8);
                    break;
                default:
                    throw new error_1.LinerError(webcrypto_core_1.AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            return res.buffer;
        });
    };
    AesCrypto.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var crypto;
        return Promise.resolve()
            .then(function () {
            crypto = new crypto_1.Crypto();
            return crypto.subtle.exportKey(format, key);
        })
            .then(function (data) {
            var raw;
            if (!(data instanceof ArrayBuffer)) {
                // JWK
                raw = helper_1.string2buffer(JSON.stringify(data));
            }
            else {
                // ArrayBuffer
                raw = new Uint8Array(data);
            }
            return crypto.subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
        });
    };
    AesCrypto.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var crypto;
        return Promise.resolve()
            .then(function () {
            crypto = new crypto_1.Crypto();
            return crypto.subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
        })
            .then(function (data) {
            var dataAny;
            if (format.toLowerCase() === "jwk") {
                dataAny = JSON.parse(helper_1.buffer2string(new Uint8Array(data)));
            }
            else {
                dataAny = new Uint8Array(data);
            }
            return crypto.subtle.importKey(format, dataAny, unwrappedKeyAlgorithm, extractable, keyUsages);
        });
    };
    AesCrypto.alg2jwk = function (alg) {
        return "A" + alg.length + /-(\w+)/i.exec(alg.name.toUpperCase())[1];
    };
    AesCrypto.jwk2alg = function (alg) {
        throw new Error("Not implemented");
    };
    AesCrypto.exportKey = function (format, key) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            var raw = key.key;
            if (format.toLowerCase() === "jwk") {
                var jwk = {
                    alg: _this.alg2jwk(key.algorithm),
                    ext: key.extractable,
                    k: webcrypto_core_1.Base64Url.encode(raw),
                    key_ops: key.usages,
                    kty: "oct",
                };
                return jwk;
            }
            else {
                return raw.buffer;
            }
        });
    };
    AesCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return Promise.resolve()
            .then(function () {
            var raw;
            if (format.toLowerCase() === "jwk") {
                var jwk = keyData;
                raw = webcrypto_core_1.Base64Url.decode(jwk.k);
            }
            else {
                raw = new Uint8Array(keyData);
            }
            var key = new key_1.CryptoKey();
            key.algorithm = algorithm;
            key.type = "secret";
            key.usages = keyUsages;
            key.key = raw;
            return key;
        });
    };
    AesCrypto.checkModule = function () {
        if (typeof asmCrypto === "undefined") {
            throw new error_1.LinerError(error_1.LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    };
    return AesCrypto;
}(webcrypto_core_1.BaseCrypto));
exports.AesCrypto = AesCrypto;
var crypto_1 = __webpack_require__(2);


/***/ }),
/* 9 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var webcrypto_core_1 = __webpack_require__(0);
var error_1 = __webpack_require__(1);
var key_1 = __webpack_require__(5);
var helper_1 = __webpack_require__(3);
// Helper
function b2a(buffer) {
    var buf = new Uint8Array(buffer);
    var res = [];
    // tslint:disable-next-line:prefer-for-of
    for (var i = 0; i < buf.length; i++) {
        res.push(buf[i]);
    }
    return res;
}
function hex2buffer(hexString, padded) {
    if (hexString.length % 2) {
        hexString = "0" + hexString;
    }
    var res = new Uint8Array(hexString.length / 2);
    for (var i = 0; i < hexString.length; i++) {
        var c = hexString.slice(i, ++i + 1);
        res[(i - 1) / 2] = parseInt(c, 16);
    }
    // BN padding
    if (padded) {
        var len = res.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if (res.length < len) {
            res = helper_1.concat(new Uint8Array(len - res.length), res);
        }
    }
    return res;
}
function buffer2hex(buffer, padded) {
    var res = "";
    // tslint:disable-next-line:prefer-for-of
    for (var i = 0; i < buffer.length; i++) {
        var char = buffer[i].toString(16);
        res += char.length % 2 ? "0" + char : char;
    }
    // BN padding
    if (padded) {
        var len = buffer.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if ((res.length / 2) < len) {
            res = new Array(len * 2 - res.length + 1).join("0") + res;
        }
    }
    return res;
}
var EcCrypto = (function (_super) {
    __extends(EcCrypto, _super);
    function EcCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    EcCrypto.generateKey = function (algorithm, extractable, keyUsage) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            _this.checkModule();
            var alg = algorithm;
            var key = new elliptic.ec(alg.namedCurve.replace("-", "").toLowerCase()); // converts name to 'p192', ...
            // set key params
            var prvKey = new key_1.CryptoKey();
            var pubKey = new key_1.CryptoKey();
            prvKey.key = pubKey.key = key.genKeyPair();
            prvKey.algorithm = pubKey.algorithm = alg;
            prvKey.extractable = extractable;
            pubKey.extractable = true;
            prvKey.type = "private";
            pubKey.type = "public";
            if (algorithm.name === webcrypto_core_1.AlgorithmNames.EcDSA) {
                prvKey.usages = ["sign"];
                pubKey.usages = ["verify"];
            }
            else if (algorithm.name === webcrypto_core_1.AlgorithmNames.EcDH) {
                prvKey.usages = ["deriveKey", "deriveBits"];
                pubKey.usages = [];
            }
            return {
                privateKey: prvKey,
                publicKey: pubKey,
            };
        });
    };
    EcCrypto.sign = function (algorithm, key, data) {
        return Promise.resolve()
            .then(function () {
            var alg = algorithm;
            // get digest
            var crypto = new crypto_1.Crypto();
            return crypto.subtle.digest(alg.hash, data);
        })
            .then(function (hash) {
            var array = b2a(hash);
            var signature = key.key.sign(array);
            var hexSignature = buffer2hex(signature.r.toArray(), true) + buffer2hex(signature.s.toArray(), true);
            return hex2buffer(hexSignature).buffer;
        });
    };
    EcCrypto.verify = function (algorithm, key, signature, data) {
        var sig;
        return Promise.resolve()
            .then(function () {
            var alg = algorithm;
            sig = {
                r: signature.slice(0, signature.byteLength / 2),
                s: signature.slice(signature.byteLength / 2),
            };
            // get digest
            var crypto = new crypto_1.Crypto();
            return crypto.subtle.digest(alg.hash, data);
        })
            .then(function (hash) {
            var array = b2a(hash);
            return (key.key.verify(array, sig));
        });
    };
    EcCrypto.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            return _this.deriveBits(algorithm, baseKey, derivedKeyType.length);
        })
            .then(function (bits) {
            var crypto = new crypto_1.Crypto();
            return crypto.subtle.importKey("raw", new Uint8Array(bits), derivedKeyType, extractable, keyUsages);
        });
    };
    EcCrypto.deriveBits = function (algorithm, baseKey, length) {
        return Promise.resolve()
            .then(function () {
            var promise = Promise.resolve(null);
            var shared = baseKey.key.derive(algorithm.public.key.getPublic());
            var array = new Uint8Array(shared.toArray());
            // Padding
            var len = array.length;
            len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
            if (array.length < len) {
                array = helper_1.concat(new Uint8Array(len - array.length), array);
            }
            var buf = array.slice(0, length / 8).buffer;
            return buf;
        });
    };
    EcCrypto.exportKey = function (format, key) {
        return Promise.resolve()
            .then(function () {
            var ecKey = key.key;
            if (format.toLowerCase() === "jwk") {
                var hexPub = ecKey.getPublic("hex").slice(2); // ignore first '04'
                var hexX = hexPub.slice(0, hexPub.length / 2);
                var hexY = hexPub.slice(hexPub.length / 2, hexPub.length);
                if (key.type === "public") {
                    // public
                    var jwk = {
                        crv: key.algorithm.namedCurve,
                        ext: key.extractable,
                        x: webcrypto_core_1.Base64Url.encode(hex2buffer(hexX, true)),
                        y: webcrypto_core_1.Base64Url.encode(hex2buffer(hexY, true)),
                        key_ops: key.usages,
                        kty: "EC",
                    };
                    return jwk;
                }
                else {
                    // private
                    var jwk = {
                        crv: key.algorithm.namedCurve,
                        ext: key.extractable,
                        d: webcrypto_core_1.Base64Url.encode(hex2buffer(ecKey.getPrivate("hex"), true)),
                        x: webcrypto_core_1.Base64Url.encode(hex2buffer(hexX, true)),
                        y: webcrypto_core_1.Base64Url.encode(hex2buffer(hexY, true)),
                        key_ops: key.usages,
                        kty: "EC",
                    };
                    return jwk;
                }
            }
            else {
                throw new error_1.LinerError("Format '" + format + "' is not implemented");
            }
        });
    };
    EcCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return Promise.resolve()
            .then(function () {
            var key = new key_1.CryptoKey();
            key.algorithm = algorithm;
            if (format.toLowerCase() === "jwk") {
                var ecKey = new elliptic.ec(keyData.crv.replace("-", "").toLowerCase());
                if (keyData.d) {
                    // Private key
                    key.key = ecKey.keyFromPrivate(webcrypto_core_1.Base64Url.decode(keyData.d));
                    key.type = "private";
                }
                else {
                    // Public key
                    var bufferPubKey = helper_1.concat(new Uint8Array([4]), webcrypto_core_1.Base64Url.decode(keyData.x), webcrypto_core_1.Base64Url.decode(keyData.y));
                    var hexPubKey = buffer2hex(bufferPubKey);
                    key.key = ecKey.keyFromPublic(hexPubKey, "hex");
                    key.type = "public";
                }
            }
            else {
                throw new error_1.LinerError("Format '" + format + "' is not implemented");
            }
            key.extractable = extractable;
            key.usages = keyUsages;
            return key;
        });
    };
    EcCrypto.checkModule = function () {
        if (typeof elliptic === "undefined") {
            throw new error_1.LinerError(error_1.LinerError.MODULE_NOT_FOUND, "elliptic", "https://github.com/indutny/elliptic");
        }
    };
    return EcCrypto;
}(webcrypto_core_1.BaseCrypto));
exports.EcCrypto = EcCrypto;
var crypto_1 = __webpack_require__(2);


/***/ }),
/* 10 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var webcrypto_core_1 = __webpack_require__(0);
var error_1 = __webpack_require__(1);
var helper_1 = __webpack_require__(3);
var key_1 = __webpack_require__(5);
function removeLeadingZero(buf) {
    var first = true;
    return buf.filter(function (v) {
        if (first && v === 0) {
            return false;
        }
        else {
            first = false;
            return true;
        }
    });
}
var RsaCrypto = (function (_super) {
    __extends(RsaCrypto, _super);
    function RsaCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    RsaCrypto.generateKey = function (alg, extractable, keyUsage) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            _this.checkModule();
            var pubExp = alg.publicExponent[0] === 3 ? 3 : 65537;
            var rsaKey = asmCrypto.RSA.generateKey(alg.modulusLength, pubExp);
            var privateKey = new key_1.CryptoKey();
            var publicKey = new key_1.CryptoKey();
            privateKey.key = publicKey.key = rsaKey;
            privateKey.algorithm = publicKey.algorithm = alg;
            privateKey.extractable = extractable;
            publicKey.extractable = true;
            privateKey.type = "private";
            publicKey.type = "public";
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    privateKey.usages = _this.filterUsages(["decrypt", "unwrapKey"], keyUsage);
                    publicKey.usages = _this.filterUsages(["encrypt", "wrapKey"], keyUsage);
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                    privateKey.usages = _this.filterUsages(["sign"], keyUsage);
                    publicKey.usages = _this.filterUsages(["verify"], keyUsage);
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, alg.name);
            }
            return { privateKey: privateKey, publicKey: publicKey };
        });
    };
    RsaCrypto.sign = function (algorithm, key, data) {
        return Promise.resolve()
            .then(function () {
            switch (algorithm.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase(): {
                    var keyAlg = key.algorithm;
                    var rsaAlg = algorithm;
                    var sign = void 0;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case webcrypto_core_1.AlgorithmNames.Sha1:
                            sign = asmCrypto.RSA_PKCS1_v1_5_SHA1.sign;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha256:
                            sign = asmCrypto.RSA_PKCS1_v1_5_SHA256.sign;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha512:
                            sign = asmCrypto.RSA_PKCS1_v1_5_SHA512.sign;
                            break;
                        default:
                            throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    return sign(data, key.key).buffer;
                }
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase(): {
                    var keyAlg = key.algorithm;
                    var rsaAlg = algorithm;
                    var sign = void 0;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case webcrypto_core_1.AlgorithmNames.Sha1:
                            sign = asmCrypto.RSA_PSS_SHA1.sign;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha256:
                            sign = asmCrypto.RSA_PSS_SHA256.sign;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha512:
                            sign = asmCrypto.RSA_PSS_SHA512.sign;
                            break;
                        default:
                            throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    return sign(data, key.key, rsaAlg.saltLength).buffer;
                }
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    };
    RsaCrypto.verify = function (algorithm, key, signature, data) {
        return Promise.resolve()
            .then(function () {
            switch (algorithm.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase(): {
                    var keyAlg_1 = key.algorithm;
                    var rsaAlg_1 = algorithm;
                    var verify_1;
                    switch (keyAlg_1.hash.name.toUpperCase()) {
                        case webcrypto_core_1.AlgorithmNames.Sha1:
                            verify_1 = asmCrypto.RSA_PKCS1_v1_5_SHA1.verify;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha256:
                            verify_1 = asmCrypto.RSA_PKCS1_v1_5_SHA256.verify;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha512:
                            verify_1 = asmCrypto.RSA_PKCS1_v1_5_SHA512.verify;
                            break;
                        default:
                            throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    try {
                        return verify_1(signature, data, key.key);
                    }
                    catch (err) {
                        console.warn("Verify error: " + err.message);
                        return false;
                    }
                }
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                    var keyAlg = key.algorithm;
                    var rsaAlg = algorithm;
                    var verify = void 0;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case webcrypto_core_1.AlgorithmNames.Sha1:
                            verify = asmCrypto.RSA_PSS_SHA1.verify;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha256:
                            verify = asmCrypto.RSA_PSS_SHA256.verify;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha512:
                            verify = asmCrypto.RSA_PSS_SHA512.verify;
                            break;
                        default:
                            throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    try {
                        return verify(signature, data, key.key, rsaAlg.saltLength);
                    }
                    catch (err) {
                        console.warn("Verify error: " + err.message);
                        return false;
                    }
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    };
    RsaCrypto.encrypt = function (algorithm, key, data) {
        return Promise.resolve()
            .then(function () {
            switch (algorithm.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    var keyAlg = key.algorithm;
                    var rsaAlg = algorithm;
                    var encrypt = void 0;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case webcrypto_core_1.AlgorithmNames.Sha1:
                            encrypt = asmCrypto.RSA_OAEP_SHA1.encrypt;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha256:
                            encrypt = asmCrypto.RSA_OAEP_SHA256.encrypt;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha512:
                            encrypt = asmCrypto.RSA_OAEP_SHA512.encrypt;
                            break;
                        default:
                            throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, keyAlg.name + " " + keyAlg.hash.name);
                    }
                    var label = void 0;
                    if (rsaAlg.label) {
                        label = webcrypto_core_1.PrepareData(rsaAlg.label, "label");
                    }
                    return encrypt(data, key.key, label);
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    };
    RsaCrypto.decrypt = function (algorithm, key, data) {
        return Promise.resolve()
            .then(function () {
            switch (algorithm.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    var keyAlg = key.algorithm;
                    var rsaAlg = algorithm;
                    var decrypt = void 0;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case webcrypto_core_1.AlgorithmNames.Sha1:
                            decrypt = asmCrypto.RSA_OAEP_SHA1.decrypt;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha256:
                            decrypt = asmCrypto.RSA_OAEP_SHA256.decrypt;
                            break;
                        case webcrypto_core_1.AlgorithmNames.Sha512:
                            decrypt = asmCrypto.RSA_OAEP_SHA512.decrypt;
                            break;
                        default:
                            throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, keyAlg.name + " " + keyAlg.hash.name);
                    }
                    var label = void 0;
                    if (rsaAlg.label) {
                        label = webcrypto_core_1.PrepareData(rsaAlg.label, "label");
                    }
                    return decrypt(data, key.key, label);
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    };
    RsaCrypto.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var crypto;
        return Promise.resolve()
            .then(function () {
            crypto = new crypto_1.Crypto();
            return crypto.subtle.exportKey(format, key);
        })
            .then(function (data) {
            var raw;
            if (!(data instanceof ArrayBuffer)) {
                // JWK
                raw = helper_1.string2buffer(JSON.stringify(data));
            }
            else {
                // ArrayBuffer
                raw = new Uint8Array(data);
            }
            return crypto.subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
        });
    };
    RsaCrypto.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var crypto;
        return Promise.resolve()
            .then(function () {
            crypto = new crypto_1.Crypto();
            return crypto.subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
        })
            .then(function (data) {
            var preparedData;
            if (format.toLowerCase() === "jwk") {
                preparedData = JSON.parse(helper_1.buffer2string(new Uint8Array(data)));
            }
            else {
                preparedData = new Uint8Array(data);
            }
            return crypto.subtle.importKey(format, preparedData, unwrappedKeyAlgorithm, extractable, keyUsages);
        });
    };
    RsaCrypto.alg2jwk = function (alg) {
        var hash = alg.hash;
        var hashSize = /(\d+)/.exec(hash.name)[1];
        switch (alg.name.toUpperCase()) {
            case webcrypto_core_1.AlgorithmNames.RsaOAEP.toUpperCase():
                return "RSA-OAEP" + (hashSize === "1" ? "" : "-" + hashSize);
            case webcrypto_core_1.AlgorithmNames.RsaPSS.toUpperCase():
                return "PS" + hashSize;
            case webcrypto_core_1.AlgorithmNames.RsaSSA.toUpperCase():
                return "RS" + hashSize;
            default:
                throw new webcrypto_core_1.AlgorithmError(webcrypto_core_1.AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
        }
    };
    RsaCrypto.jwk2alg = function (alg) {
        throw new Error("Not implemented");
    };
    RsaCrypto.exportKey = function (format, key) {
        var _this = this;
        return Promise.resolve()
            .then(function () {
            if (format.toLowerCase() === "jwk") {
                var jwk = {
                    kty: "RSA",
                    ext: true,
                    key_ops: key.usages,
                };
                jwk.alg = _this.alg2jwk(key.algorithm);
                jwk.n = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[0]));
                jwk.e = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[1]));
                if (key.type === "private") {
                    jwk.d = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[2]));
                    jwk.p = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[3]));
                    jwk.q = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[4]));
                    jwk.dp = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[5]));
                    jwk.dq = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[6]));
                    jwk.qi = webcrypto_core_1.Base64Url.encode(removeLeadingZero(key.key[7]));
                }
                return jwk;
            }
            else {
                throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED);
            }
        });
    };
    RsaCrypto.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        return Promise.resolve()
            .then(function () {
            var jwk;
            var key = new key_1.CryptoKey();
            key.algorithm = algorithm;
            key.usages = keyUsages;
            key.key = [];
            if (format.toLowerCase() === "jwk") {
                jwk = keyData;
                key.key[0] = webcrypto_core_1.Base64Url.decode(jwk.n);
                key.key[1] = webcrypto_core_1.Base64Url.decode(jwk.e)[0] === 3 ? new Uint8Array([0, 0, 0, 3]) : new Uint8Array([0, 1, 0, 1]);
                if (jwk.d) {
                    key.type = "private";
                    key.key[2] = webcrypto_core_1.Base64Url.decode(jwk.d);
                    key.key[3] = webcrypto_core_1.Base64Url.decode(jwk.p);
                    key.key[4] = webcrypto_core_1.Base64Url.decode(jwk.q);
                    key.key[5] = webcrypto_core_1.Base64Url.decode(jwk.dp);
                    key.key[6] = webcrypto_core_1.Base64Url.decode(jwk.dq);
                    key.key[7] = webcrypto_core_1.Base64Url.decode(jwk.qi);
                }
                else {
                    key.type = "public";
                }
                return key;
            }
            else {
                throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED);
            }
        });
    };
    RsaCrypto.checkModule = function () {
        if (typeof asmCrypto === "undefined") {
            throw new error_1.LinerError(error_1.LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    };
    RsaCrypto.filterUsages = function (supported, given) {
        return supported.filter(function (item1) { return !!given.filter(function (item2) { return item1 === item2; }).length; });
    };
    return RsaCrypto;
}(webcrypto_core_1.BaseCrypto));
exports.RsaCrypto = RsaCrypto;
var crypto_1 = __webpack_require__(2);


/***/ }),
/* 11 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var webcrypto_core_1 = __webpack_require__(0);
var error_1 = __webpack_require__(1);
var ShaCrypto = (function (_super) {
    __extends(ShaCrypto, _super);
    function ShaCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    ShaCrypto.digest = function (alg, message) {
        return Promise.resolve()
            .then(function () {
            if (typeof asmCrypto === "undefined") {
                throw new error_1.LinerError(error_1.LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
            }
            switch (alg.name.toUpperCase()) {
                case webcrypto_core_1.AlgorithmNames.Sha1:
                    return asmCrypto.SHA1.bytes(message).buffer;
                case webcrypto_core_1.AlgorithmNames.Sha256:
                    return asmCrypto.SHA256.bytes(message).buffer;
                case webcrypto_core_1.AlgorithmNames.Sha512:
                    return asmCrypto.SHA512.bytes(message).buffer;
                default:
                    throw new error_1.LinerError("Not supported algorithm '" + alg.name + "'");
            }
        });
    };
    return ShaCrypto;
}(webcrypto_core_1.BaseCrypto));
exports.ShaCrypto = ShaCrypto;


/***/ }),
/* 12 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
// Core
var webcrypto_core_1 = __webpack_require__(0);
var core = __webpack_require__(0);
var webcrypto_core_2 = __webpack_require__(0);
// Base
var init_1 = __webpack_require__(4);
var crypto_1 = __webpack_require__(2);
var error_1 = __webpack_require__(1);
var helper_1 = __webpack_require__(3);
// Crypto
var crypto_2 = __webpack_require__(8);
var crypto_3 = __webpack_require__(11);
var crypto_4 = __webpack_require__(10);
var crypto_5 = __webpack_require__(9);
var keys = [];
function PrepareKey(key, subtle) {
    return Promise.resolve()
        .then(function () {
        if (!key.key) {
            if (!key.extractable) {
                throw new error_1.LinerError("'key' is Native CryptoKey. It can't be converted to JS CryptoKey");
            }
            else {
                var crypto_6 = new crypto_1.Crypto();
                return crypto_6.subtle.exportKey("jwk", key)
                    .then(function (jwk) {
                    var alg = GetHashAlgorithm(key);
                    if (alg) {
                        alg = helper_1.assign(alg, key.algorithm);
                    }
                    return subtle.importKey("jwk", jwk, alg, true, key.usages);
                });
            }
        }
        else {
            return key;
        }
    });
}
var SubtleCrypto = (function (_super) {
    __extends(SubtleCrypto, _super);
    function SubtleCrypto() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    SubtleCrypto.prototype.generateKey = function (algorithm, extractable, keyUsages) {
        var args = arguments;
        var alg;
        return _super.prototype.generateKey.apply(this, args)
            .then(function (d) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            if (helper_1.BrowserInfo().name === helper_1.Browser.Edge && alg.name.toUpperCase() === webcrypto_core_1.AlgorithmNames.AesGCM) {
                // Don't do AES-GCM key generation, because Edge throws errors on GCM encrypt, decrypt, wrapKey, unwrapKey
                return;
            }
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.generateKey.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native generateKey for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native generateKey for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (generatedKeys) {
            if (generatedKeys) {
                FixCryptoKeyUsages(generatedKeys, keyUsages);
                SetHashAlgorithm(alg, generatedKeys);
                return generatedKeys;
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                    Class = crypto_2.AesCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.EcDSA.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.EcDH.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return Class.generateKey(alg, extractable, keyUsages);
        });
    };
    SubtleCrypto.prototype.digest = function (algorithm, data) {
        var args = arguments;
        var alg;
        var dataBytes;
        return _super.prototype.digest.apply(this, args)
            .then(function (d) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            dataBytes = webcrypto_core_2.PrepareData(data, "data");
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.digest.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native digest for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native digest for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (digest) {
            if (digest) {
                return digest;
            }
            return crypto_3.ShaCrypto.digest(alg, dataBytes);
        });
    };
    SubtleCrypto.prototype.sign = function (algorithm, key, data) {
        var args = arguments;
        var alg;
        var dataBytes;
        return _super.prototype.sign.apply(this, args)
            .then(function (d) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            dataBytes = webcrypto_core_2.PrepareData(data, "data");
            var alg2 = GetHashAlgorithm(key);
            if (alg2) {
                args[0] = helper_1.assign(alg, alg2);
            }
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.sign.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native sign for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native sign for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (signature) {
            if (signature) {
                return signature;
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.EcDSA.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return PrepareKey(key, Class)
                .then(function (preparedKey) { return Class.sign(alg, preparedKey, dataBytes); });
        });
    };
    SubtleCrypto.prototype.verify = function (algorithm, key, signature, data) {
        var args = arguments;
        var alg;
        var signatureBytes;
        var dataBytes;
        return _super.prototype.verify.apply(this, args)
            .then(function (d) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            signatureBytes = webcrypto_core_2.PrepareData(signature, "data");
            dataBytes = webcrypto_core_2.PrepareData(data, "data");
            var alg2 = GetHashAlgorithm(key);
            if (alg2) {
                args[0] = helper_1.assign(alg, alg2);
            }
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.verify.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native verify for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native verify for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (result) {
            if (typeof result === "boolean") {
                return result;
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.EcDSA.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return PrepareKey(key, Class)
                .then(function (preparedKey) { return Class.verify(alg, preparedKey, signatureBytes, dataBytes); });
        });
    };
    SubtleCrypto.prototype.deriveBits = function (algorithm, baseKey, length) {
        var args = arguments;
        var alg;
        return _super.prototype.deriveBits.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.deriveBits.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native deriveBits for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    // Edge throws error. Don't know Why.
                    console.warn("WebCrypto: native deriveBits for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (bits) {
            if (bits) {
                return bits;
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.EcDH.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED, "deriveBits");
            }
            return Class.deriveBits(alg, baseKey, length);
        });
    };
    SubtleCrypto.prototype.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var args = arguments;
        var alg;
        var algDerivedKey;
        return _super.prototype.deriveKey.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            algDerivedKey = webcrypto_core_2.PrepareAlgorithm(derivedKeyType);
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.deriveKey.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native deriveKey for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    // Edge doesn't go to catch of Promise
                    console.warn("WebCrypto: native deriveKey for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (key) {
            if (key) {
                FixCryptoKeyUsages(key, keyUsages);
                return key;
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.EcDH.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED, "deriveBits");
            }
            return Class.deriveKey(alg, baseKey, algDerivedKey, extractable, keyUsages);
        });
    };
    SubtleCrypto.prototype.encrypt = function (algorithm, key, data) {
        var args = arguments;
        var alg;
        var dataBytes;
        return _super.prototype.encrypt.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            dataBytes = webcrypto_core_2.PrepareData(data, "data");
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.encrypt.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native 'encrypt' for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native 'encrypt' for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (msg) {
            if (msg) {
                if (helper_1.BrowserInfo().name === helper_1.Browser.IE &&
                    alg.name.toUpperCase() === webcrypto_core_1.AlgorithmNames.AesGCM &&
                    msg.ciphertext) {
                    // Concatenate values in IE
                    var buf_1 = new Uint8Array(msg.ciphertext.byteLength + msg.tag.byteLength);
                    var count_1 = 0;
                    new Uint8Array(msg.ciphertext).forEach(function (v) { return buf_1[count_1++] = v; });
                    new Uint8Array(msg.tag).forEach(function (v) { return buf_1[count_1++] = v; });
                    msg = buf_1.buffer;
                }
                return Promise.resolve(msg);
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                    Class = crypto_2.AesCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED, "encrypt");
            }
            return PrepareKey(key, Class)
                .then(function (preparedKey) { return Class.encrypt(alg, preparedKey, dataBytes); });
        });
    };
    SubtleCrypto.prototype.decrypt = function (algorithm, key, data) {
        var args = arguments;
        var alg;
        var dataBytes;
        return _super.prototype.decrypt.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            dataBytes = webcrypto_core_2.PrepareData(data, "data");
            var dataBytes2 = dataBytes;
            if (helper_1.BrowserInfo().name === helper_1.Browser.IE &&
                alg.name.toUpperCase() === webcrypto_core_1.AlgorithmNames.AesGCM) {
                // Split buffer
                var len = dataBytes.byteLength - (alg.tagLength / 8);
                dataBytes2 = {
                    ciphertext: dataBytes.buffer.slice(0, len),
                    tag: dataBytes.buffer.slice(len, dataBytes.byteLength),
                };
            }
            if (!key.key) {
                return init_1.nativeSubtle.decrypt.call(init_1.nativeSubtle, alg, key, dataBytes2);
            }
            else {
                var Class = void 0;
                switch (alg.name.toLowerCase()) {
                    case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                    case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                    case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                        Class = crypto_2.AesCrypto;
                        break;
                    case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = crypto_4.RsaCrypto;
                        break;
                    default:
                        throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED, "decrypt");
                }
                return Class.decrypt(alg, key, dataBytes);
            }
        });
    };
    SubtleCrypto.prototype.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var args = arguments;
        var alg;
        return _super.prototype.wrapKey.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(wrapAlgorithm);
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.wrapKey.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native 'wrapKey' for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native 'wrapKey' for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (msg) {
            if (msg) {
                return msg;
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                    Class = crypto_2.AesCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED, "wrapKey");
            }
            return Class.wrapKey(format, key, wrappingKey, alg);
        });
    };
    SubtleCrypto.prototype.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var _this = this;
        var args = arguments;
        var alg;
        var algKey;
        var dataBytes;
        return _super.prototype.unwrapKey.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(unwrapAlgorithm);
            algKey = webcrypto_core_2.PrepareAlgorithm(unwrappedKeyAlgorithm);
            dataBytes = webcrypto_core_2.PrepareData(wrappedKey, "wrappedKey");
            if (!unwrappingKey.key) {
                return init_1.nativeSubtle.unwrapKey.apply(init_1.nativeSubtle, args)
                    .catch(function (err) {
                    // Edge throws errors on unwrapKey native functions
                    // Use custom unwrap function
                    return _this.decrypt(alg, unwrappingKey, wrappedKey)
                        .then(function (decryptedData) {
                        var preparedData;
                        if (format === "jwk") {
                            preparedData = JSON.parse(helper_1.buffer2string(new Uint8Array(decryptedData)));
                        }
                        else {
                            preparedData = decryptedData;
                        }
                        return _this.importKey(format, preparedData, algKey, extractable, keyUsages);
                    });
                })
                    .then(function (k) {
                    if (k) {
                        FixCryptoKeyUsages(k, keyUsages);
                        return k;
                    }
                })
                    .catch(function (error) {
                    console.error(error);
                    throw new Error("Cannot unwrap key from incoming data");
                });
            }
            else {
                var Class = void 0;
                switch (alg.name.toLowerCase()) {
                    case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                    case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                    case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                        Class = crypto_2.AesCrypto;
                        break;
                    case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                        Class = crypto_4.RsaCrypto;
                        break;
                    default:
                        throw new error_1.LinerError(error_1.LinerError.NOT_SUPPORTED, "unwrapKey");
                }
                return Class.unwrapKey(format, dataBytes, unwrappingKey, alg, algKey, extractable, keyUsages);
            }
        });
    };
    SubtleCrypto.prototype.exportKey = function (format, key) {
        var args = arguments;
        return _super.prototype.exportKey.apply(this, args)
            .then(function () {
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.exportKey.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native 'exportKey' for " + key.algorithm.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native 'exportKey' for " + key.algorithm.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (msg) {
            if (msg) {
                if (format === "jwk" && msg instanceof ArrayBuffer) {
                    msg = helper_1.buffer2string(new Uint8Array(msg));
                    msg = JSON.parse(msg);
                }
                var alg = GetHashAlgorithm(key);
                if (!alg) {
                    alg = helper_1.assign({}, key.algorithm);
                }
                FixExportJwk(msg, alg, key.usages);
                return Promise.resolve(msg);
            }
            if (!key.key) {
                throw new error_1.LinerError("Cannot export native CryptoKey from JS implementation");
            }
            var Class;
            switch (key.algorithm.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                    Class = crypto_2.AesCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.EcDH.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.EcDSA.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name.toLowerCase());
            }
            return Class.exportKey(format, key);
        });
    };
    SubtleCrypto.prototype.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var args = arguments;
        var alg;
        var dataAny;
        return _super.prototype.importKey.apply(this, args)
            .then(function (bits) {
            alg = webcrypto_core_2.PrepareAlgorithm(algorithm);
            dataAny = keyData;
            // Fix: Safari
            var browser = helper_1.BrowserInfo();
            if (format === "jwk" && ((browser.name === helper_1.Browser.Safari && !/^11/.test(browser.version)) ||
                browser.name === helper_1.Browser.IE)) {
                // Converts JWK to ArrayBuffer
                if (helper_1.BrowserInfo().name === helper_1.Browser.IE) {
                    keyData = helper_1.assign({}, keyData);
                    FixImportJwk(keyData);
                }
                args[1] = helper_1.string2buffer(JSON.stringify(keyData)).buffer;
            }
            // End: Fix
            if (ArrayBuffer.isView(keyData)) {
                dataAny = webcrypto_core_2.PrepareData(keyData, "keyData");
            }
            if (init_1.nativeSubtle) {
                try {
                    return init_1.nativeSubtle.importKey.apply(init_1.nativeSubtle, args)
                        .catch(function (e) {
                        console.warn("WebCrypto: native 'importKey' for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    console.warn("WebCrypto: native 'importKey' for " + alg.name + " doesn't work.", e && e.message || "Unknown message");
                }
            }
        })
            .then(function (k) {
            if (k) {
                SetHashAlgorithm(alg, k);
                FixCryptoKeyUsages(k, keyUsages);
                return Promise.resolve(k);
            }
            var Class;
            switch (alg.name.toLowerCase()) {
                case webcrypto_core_1.AlgorithmNames.AesECB.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesCBC.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.AesGCM.toLowerCase():
                    Class = crypto_2.AesCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.EcDH.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.EcDSA.toLowerCase():
                    Class = crypto_5.EcCrypto;
                    break;
                case webcrypto_core_1.AlgorithmNames.RsaSSA.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaPSS.toLowerCase():
                case webcrypto_core_1.AlgorithmNames.RsaOAEP.toLowerCase():
                    Class = crypto_4.RsaCrypto;
                    break;
                default:
                    throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return Class.importKey(format, dataAny, alg, extractable, keyUsages);
        });
    };
    return SubtleCrypto;
}(core.SubtleCrypto));
exports.SubtleCrypto = SubtleCrypto;
// save hash alg for RSA keys
function SetHashAlgorithm(alg, key) {
    if ((helper_1.BrowserInfo().name === helper_1.Browser.IE || helper_1.BrowserInfo().name === helper_1.Browser.Edge || helper_1.BrowserInfo().name === helper_1.Browser.Safari) && /^rsa/i.test(alg.name)) {
        if (key.privateKey) {
            keys.push({ hash: alg.hash, key: key.privateKey });
            keys.push({ hash: alg.hash, key: key.publicKey });
        }
        else {
            keys.push({ hash: alg.hash, key: key });
        }
    }
}
// fix hash alg for rsa key
function GetHashAlgorithm(key) {
    var alg = null;
    keys.some(function (item) {
        if (item.key === key) {
            alg = helper_1.assign({}, key.algorithm, { hash: item.hash });
            return true;
        }
        return false;
    });
    return alg;
}
// Extend Uint8Array for IE
if (!Uint8Array.prototype.forEach) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    Uint8Array.prototype.forEach = function (cb) {
        for (var i = 0; i < this.length; i++) {
            cb(this[i], i, this);
        }
    };
}
if (!Uint8Array.prototype.slice) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    Uint8Array.prototype.slice = function (start, end) {
        return new Uint8Array(this.buffer.slice(start, end));
    };
}
if (!Uint8Array.prototype.filter) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    Uint8Array.prototype.filter = function (cb) {
        var buf = [];
        for (var i = 0; i < this.length; i++) {
            if (cb(this[i], i, this)) {
                buf.push(this[i]);
            }
        }
        return new Uint8Array(buf);
    };
}
function FixCryptoKeyUsages(key, keyUsages) {
    var keyArray = [];
    if (key.privateKey) {
        keyArray.push(key.privateKey);
        keyArray.push(key.publicKey);
    }
    else {
        keyArray.push(key);
    }
    keyArray.forEach(function (k) {
        if ("keyUsage" in k) {
            k.usages = k.keyUsage || [];
            // add usages
            if (!k.usages.length) {
                ["verify", "encrypt", "wrapKey"]
                    .forEach(function (usage) {
                    if (keyUsages.indexOf(usage) > -1 && (k.type === "public" || k.type === "secret")) {
                        k.usages.push(usage);
                    }
                });
                ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"]
                    .forEach(function (usage) {
                    if (keyUsages.indexOf(usage) > -1 && (k.type === "private" || k.type === "secret")) {
                        k.usages.push(usage);
                    }
                });
            }
        }
    });
}
function FixExportJwk(jwk, alg, keyUsages) {
    if (alg && helper_1.BrowserInfo().name === helper_1.Browser.IE) {
        // ext
        if ("extractable" in jwk) {
            jwk.ext = jwk.extractable;
            delete jwk.extractable;
        }
        // add alg
        var CryptoClass = null;
        switch (alg.name.toUpperCase()) {
            case webcrypto_core_1.AlgorithmNames.RsaOAEP.toUpperCase():
            case webcrypto_core_1.AlgorithmNames.RsaPSS.toUpperCase():
            case webcrypto_core_1.AlgorithmNames.RsaSSA.toUpperCase():
                CryptoClass = crypto_4.RsaCrypto;
                break;
            case webcrypto_core_1.AlgorithmNames.AesECB.toUpperCase():
            case webcrypto_core_1.AlgorithmNames.AesCBC.toUpperCase():
            case webcrypto_core_1.AlgorithmNames.AesGCM.toUpperCase():
                CryptoClass = crypto_2.AesCrypto;
                break;
            default:
                throw new error_1.LinerError(error_1.LinerError.UNSUPPORTED_ALGORITHM, alg.name.toUpperCase());
        }
        if (CryptoClass && !jwk.alg) {
            jwk.alg = CryptoClass.alg2jwk(alg);
        }
        // add key_ops
        if (!("key_ops" in jwk)) {
            jwk.key_ops = keyUsages;
        }
    }
}
function FixImportJwk(jwk) {
    if (helper_1.BrowserInfo().name === helper_1.Browser.IE) {
        // ext
        if ("ext" in jwk) {
            jwk.extractable = jwk.ext;
            delete jwk.ext;
        }
        delete jwk.key_ops;
        delete jwk.alg;
    }
}


/***/ }),
/* 13 */
/***/ (function(module, exports) {

var g;

// This works in non-strict mode
g = (function() {
	return this;
})();

try {
	// This works if eval is allowed (see CSP)
	g = g || Function("return this")() || (1,eval)("this");
} catch(e) {
	// This works if the window reference is available
	if(typeof window === "object")
		g = window;
}

// g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}

module.exports = g;


/***/ }),
/* 14 */
/***/ (function(module, exports) {

module.exports = require("crypto");;

/***/ }),
/* 15 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = __webpack_require__(7);
// Object.freeze(Math);
// Object.freeze(Math.random);
// Object.freeze((Math as any).imul);
if (index_1.nativeCrypto) {
    Object.freeze(index_1.nativeCrypto.getRandomValues);
}
exports.crypto = new index_1.Crypto();


/***/ })
/******/ ]);