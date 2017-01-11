var worker = new Worker("src/crypto.js");

function sign() {
    var $result = document.getElementById("result")
    $result.style.color = "blue";
    $result.textContent = "Loading...";

    var $text = document.getElementById("text")
    worker.postMessage(["sign", $text.value]);
}

function verify() {
    var $result = document.getElementById("verify_result")
    $result.style.color = "blue";
    $result.textContent = "Loading...";

    var $text = document.getElementById("signed_text");
    var $jwk = document.getElementById("jwk");
    var $signature = document.getElementById("signature");

    var jwk = JSON.parse($jwk.value);
    var text = atob(btoa($text.value));
    var signature = atob($signature.value);
    worker.postMessage(["verify", jwk, signature, text]);
}

worker.onmessage = function (e) {
    switch (e.data[0]) {
        case "seed":
            var seed = "";
            var crypto = self.crypto || self.msCrypto;
            var buf = crypto.getRandomValues(new Uint8Array(e.data[1]));
            for (var i = 0; i < buf.length; i++)
                seed += String.fromCharCode(buf[i]);
            worker.postMessage(["seed", seed]);
            break;
        case "key":
            console.log("Key", e.data[1]);
            break;
        case "verify":
            var $result = document.getElementById("verify_result")
            if (e.data[1])
                $result.style.color = "green";
            else
                $result.style.color = "red";
            $result.textContent = e.data[1].toString();
            break;
        case "sign":
            var $result = document.getElementById("result")
            $result.style.color = "green";
            $result.textContent = btoa(e.data[1]);

            // set data for verify
            var $text = document.getElementById("signed_text");
            $text.value = document.getElementById("text").value;
            var $jwk = document.getElementById("jwk");
            $jwk.value = e.data[2];
            var $signature = document.getElementById("signature");
            $signature.value = btoa(e.data[1]);
            break;
        case "error":
            error(e.data[1]);
            break;
        default:
            alert("Unknown command from WebWorker '" + e.data[0] + "'");

    }
}
worker.onerror = function (e) {
    error(e);
}

function error(e) {
    alert(e.message);
    console.error(e.stack);
}