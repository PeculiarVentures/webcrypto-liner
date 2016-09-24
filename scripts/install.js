/// <reference path="../typings/index.d.ts" />

var fs = require("fs");
var os = require("os");
var FILE_ENCODING = "utf-8";

function concat(files, distPath) {
    var out = files.map(function (file) {
        if (!fs.existsSync(file))
            throw new Error("File '" + file + "' doesn't exist");
        return fs.readFileSync(file, FILE_ENCODING);
    });
    fs.writeFileSync(distPath, out.join(os.EOL), FILE_ENCODING);
    console.log(distPath + " built.");
}

concat([
   "node_modules/webcrypto-core/build/webcrypto-core.min.js", 
   "build/webcrypto-liner.min.js" 
], "webcrypto-liner.min.js");
concat([
   "node_modules/webcrypto-core/build/webcrypto-core.js", 
   "build/webcrypto-liner.js" 
], "webcrypto-liner.js");
