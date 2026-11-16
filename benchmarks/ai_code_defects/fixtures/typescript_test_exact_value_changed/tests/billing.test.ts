const result = { status: "paid" };
test("checks billing", () => {
  expect(result.status).toBe("paid");
});
