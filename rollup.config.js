import resolve from "rollup-plugin-node-resolve";
import babel from "rollup-plugin-babel";
import builtins from "rollup-plugin-node-builtins";
import globals from "rollup-plugin-node-globals";
import typescript from "rollup-plugin-typescript";
import commonjs from "rollup-plugin-commonjs";
import pkg from "./package.json";

const dependencies = Object.keys(pkg.dependencies)
  .concat(["crypto"]);
let banner = []

export default [
  // ESNEXT bundled file for webcrypto-socket
  {
    input: "src/shim.ts",
    plugins: [
      typescript({ typescript: require("typescript"), target: "esnext", removeComments: true }),
      resolve(),
      commonjs(),
      builtins(),
    ],
    // Specify here external modules which you don"t want to include in your bundle (for instance: "lodash", "moment" etc.)
    // https://rollupjs.org/guide/en#external-e-external
    // external: ["protobufjs"],
    // external: dependencies,
    output: [
      {
        file: pkg.module,
        format: "es",
        globals: {
          "crypto": "require('crypto')"
        }
      }
    ]
  },
  // ES5 bundled file for webcrypto-liner
  {
    input: pkg.module,
    plugins: [
      babel({
        babelrc: false,
        runtimeHelpers: true,
        // exclude: 'node_modules/**',
        // include: [
        //   "build/**",
        //   "src/**",
        // ],
        // include: dependencies.map(item => `node_modules/${item}/**`).concat(["src/**"]),
        presets: [
          [
            "@babel/env",
            {
              targets: {
                // ie: "11",
                chrome: "72"
              },
              useBuiltIns: "entry"
            }
          ]
        ],
        plugins: [
          "@babel/proposal-class-properties",
          "@babel/proposal-object-rest-spread",
        ],
      }),
    ],
    external: ["crypto"],
    output: [
      {
        file: pkg.browser,
        format: "iife",
        name: "liner",
        globals: {
          "crypto": "require('crypto')",
        },
      },
    ],
  },
  // ES5 bundled tests
  {
    input: "test/script/index.ts",
    plugins: [
      typescript({ typescript: require("typescript"), target: "esnext", removeComments: true }),
      // builtins(),
      resolve(),
      commonjs(),
      globals({
        buffer: false,
        global: true,
        process: false,
        dirname: false,
        filename: false,
      }),
      babel({
        babelrc: false,
        runtimeHelpers: true,
        // exclude: 'node_modules/**',
        // include: [
        //   "build/**",
        //   "src/**",
        // ],
        // include: dependencies.map(item => `node_modules/${item}/**`).concat(["src/**"]),
        presets: [
          [
            "@babel/env",
            {
              targets: {
                google: "72"
                // ie: "11",
              },
              useBuiltIns: "entry"
            }
          ]
        ],
        plugins: [
          "@babel/proposal-class-properties",
          "@babel/proposal-object-rest-spread",
        ],
      }),
    ],
    external: [
      "assert",
    ],
    output: [
      {
        file: "test/tests.js",
        format: "iife",
        name: "liner",
        globals: {
          "assert": "assert",
        },
      },
    ],
  },
];
