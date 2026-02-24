"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_LANGUAGES = void 0;
exports.getDocumentFilters = getDocumentFilters;
exports.SUPPORTED_LANGUAGES = [
    "python",
    "typescript",
    "typescriptreact",
    "javascript",
    "javascriptreact",
    "go",
];
function getDocumentFilters() {
    return exports.SUPPORTED_LANGUAGES.map((lang) => ({ language: lang, scheme: "file" }));
}
