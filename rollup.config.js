import resolve from "@rollup/plugin-node-resolve";
import { getBabelOutputPlugin } from "@rollup/plugin-babel";
import { terser } from "rollup-plugin-terser";
import typescript from "rollup-plugin-typescript2";
import commonjs from "@rollup/plugin-commonjs";
import pkg from "./package.json";

const external = Object.keys(pkg.dependencies)
  .concat(["crypto"]);
let banner = [
  "/**",
  ` * Copyright (c) ${new Date().getFullYear()}, Peculiar Ventures, LLC.`,
  " */",
  "",
].join("\n");

const main = {
  input: "src/lib.ts",
  plugins: [
    typescript({
      check: true,
      clean: true,
      tsconfigOverride: {
        compilerOptions: {
          module: "es2015",
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

function babelOutput(ie11) {
  const targets = ie11
    ? { ie: "11" }
    : { chrome: "60" };
  return getBabelOutputPlugin({
    allowAllFormats: true,
    babelrc: false,
    runtimeHelpers: true,
    compact: false,
    comments: false,
    presets: [
      ["@babel/env", {
        targets,
        useBuiltIns: "entry",
        corejs: 3,
      }],
    ],
  });
}


//#region Browser
const browserExternals = {
  // "des.js": "des",
  "util": "{}",
  "elliptic": "self.elliptic",
  "asmcrypto.js": "self.asmCrypto",
};

const browser = [
  {
    input: "src/shim.ts",
    plugins: [
      resolve({
        mainFields: ["esnext", "module", "main"],
        preferBuiltins: true,
      }),
      // nodePolyfills(),
      commonjs(),
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "es2015",
          }
        }
      }),
    ],
    external: Object.keys(browserExternals),
    output: [
      {
        file: pkg["browser:es5"],
        format: "iife",
        globals: browserExternals,
        name: "liner",
        plugins: [
          babelOutput(true),
        ]
      },
      {
        file: pkg["browser:es5:min"],
        format: "iife",
        globals: browserExternals,
        name: "liner",
        plugins: [
          babelOutput(true),
          terser()
        ]
      },
      {
        file: pkg["browser"],
        format: "iife",
        globals: browserExternals,
        name: "liner",
        plugins: [
          babelOutput(false),
        ]
      },
      {
        file: pkg["browser:min"],
        format: "iife",
        globals: browserExternals,
        name: "liner",
        plugins: [
          babelOutput(false),
          terser()
        ]
      }
    ]
  },
];
//#endregion

export default [
  main,
  ...browser,
]