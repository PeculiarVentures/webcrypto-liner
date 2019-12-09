import resolve from "rollup-plugin-node-resolve";
import babel from "rollup-plugin-babel";
import builtins from "rollup-plugin-node-builtins";
import typescript from "rollup-plugin-typescript2";
import commonjs from "rollup-plugin-commonjs";
import cleanup from "rollup-plugin-cleanup";
import json from "rollup-plugin-json";
import pkg from "./package.json";

const external = Object.keys(pkg.dependencies)
  .concat(["crypto"]);
let banner = []

const main = {
  input: "src/lib.ts",
  plugins: [
    typescript({
      check: true,
      clean: true,
      tsconfigOverride: {
        compilerOptions: {
          module: "es6",
          removeComments: true,
        }
      }
    }),
  ],
  external,
  output: [
    {
      banner,
      file: pkg.main,
      format: "cjs",
    },
    {
      banner,
      file: pkg.module,
      format: "es",
    },
  ],
};


//#region Browser
const browserExternals = {
  // "des.js": "des",
  // "elliptic": "elliptic",
};

const browser = [
  {
    input: "src/shim.ts",
    plugins: [
      resolve({
        preferBuiltins: true,
      }),
      json(),
      commonjs(),
      builtins(),
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "es6",
            removeComments: true,
          }
        }
      }),
      cleanup(),
    ],
    external: Object.keys(browserExternals),
    output: [
      {
        file: pkg.browser,
        format: "es",
        globals: browserExternals,
      }
    ]
  },
  {
    input: pkg.browser,
    plugins: [
      babel({
        babelrc: false,
        runtimeHelpers: true,
        presets: [
          [
            "@babel/env",
            {
              targets: {
                ie: "11",
                chrome: "60",
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
    output: [
      {
        file: pkg.browser,
        format: "iife",
        name: "liner",
        intro: "var global = self;"
      },
    ],
  },
];
//#endregion

export default [
  main,
  ...browser,
]