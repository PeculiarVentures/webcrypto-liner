"use strict"

const path = require("path");
const webpack = require("webpack");

module.exports = [
    {
        name: "typescript",
        entry: {
            "webcrypto-liner.shim": "./src/shim.ts",
            "webcrypto-liner.lib": "./src/lib.ts",
        },
        output: {
            library: "liner",
            path: path.join(__dirname, "dist"),
            filename: "[name].js"
        },
        resolve: {
            extensions: [".webpack.js", ".web.js", ".ts", ".js"]
        },
        module: {
            rules: [
                { test: /\.ts$/, loader: "ts-loader", exclude: path.resolve(__dirname, "node_modules") }
            ]
        },
        externals: {
            crypto: "require(\"crypto\");",
        },
        node: {
            Buffer: false,
            crypto: false
        }
    }
];
