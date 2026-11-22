const defineTest = require("jscodeshift/dist/testUtils").defineTest;

defineTest(__dirname, "rename.cjs", null, "default", { parser: "tsx" });
