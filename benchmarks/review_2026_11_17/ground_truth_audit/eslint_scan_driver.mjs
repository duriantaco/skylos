import fs from 'node:fs';
import path from 'node:path';
import { ESLint } from 'eslint';
import security from 'eslint-plugin-security';
import parser from '@typescript-eslint/parser';
const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
let rows=[];
for (const target of input.targets) {
 const eslint=new ESLint({cwd:target.root,overrideConfigFile:true,ignore:false,overrideConfig:[{files:['**/*.{js,cjs,mjs,ts,cts,mts,jsx,tsx}'],languageOptions:{parser,parserOptions:{ecmaVersion:'latest',sourceType:'module',ecmaFeatures:{jsx:true}}},plugins:{security},rules:security.configs.recommended.rules}]});
 try { const results=await eslint.lintFiles(target.files);rows.push({id:target.id,root:target.root,results}); }
 catch(error) {rows.push({id:target.id,error:String(error)});}
}
fs.writeFileSync(process.argv[3],JSON.stringify({tool:'ESLint with eslint-plugin-security recommended rules',configuration:'External trusted flat config + TypeScript parser, overrideConfigFile=true; target configs/scripts never loaded',versions:{eslint:JSON.parse(fs.readFileSync(new URL('./node_modules/eslint/package.json',import.meta.url))).version,security:JSON.parse(fs.readFileSync(new URL('./node_modules/eslint-plugin-security/package.json',import.meta.url))).version,parser:JSON.parse(fs.readFileSync(new URL('./node_modules/@typescript-eslint/parser/package.json',import.meta.url))).version},targets:rows},null,2)+'\n');
