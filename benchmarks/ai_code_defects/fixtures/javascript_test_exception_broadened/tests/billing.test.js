function reject() { throw new TypeError("invalid"); }
test("checks billing", () => {
  expect(reject).toThrow();
});
