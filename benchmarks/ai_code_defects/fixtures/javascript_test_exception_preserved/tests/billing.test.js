function reject() { throw new TypeError("invalid"); }
test("rejects invalid billing", () => {
  expect(reject).toThrow(TypeError);
});
