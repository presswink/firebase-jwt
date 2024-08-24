import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";


export default [
  {files: ["**/*.{js,mjs,cjs,ts}"]},
  {languageOptions: { globals: [globals.node, globals.mocha] }},
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: ["dist/*"]
  }
];