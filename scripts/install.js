/// <reference path="../typings/index.d.ts" />
var concat = require("./concat") 

// Concat min files
concat([
   "node_modules/webcrypto-core/build/webcrypto-core.min.js", 
   "build/webcrypto-liner.min.js" 
], "webcrypto-liner.min.js");

// Concat full files
concat([
   "node_modules/webcrypto-core/build/webcrypto-core.js", 
   "build/webcrypto-liner.js" 
], "webcrypto-liner.js");
