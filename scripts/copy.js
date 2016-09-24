/// <reference path="../typings/index.d.ts" />
var fs = require("fs");
var concat = require("./concat")

if (!fs.existsSync("typings"))
    fs.mkdirSync("typings");
if (!fs.existsSync("typings/webcrypto-core"))
    fs.mkdirSync("typings/webcrypto-core");

// Copy d.ts to 
concat([
    "node_modules/webcrypto-core/build/webcrypto-core.d.ts"
], "typings/webcrypto-core/webcrypto-core.d.ts");