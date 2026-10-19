// Minimal declarations for the runtime dependencies that ship without type definitions. Only the
// members this library uses are declared.

declare module 'punycode.js' {
    // A CommonJS module, so its default import is the module object itself
    const punycode: {
        toUnicode(input: string): string;
        toASCII(input: string): string;
    };
    export default punycode;
}
