type InvoiceWriter = {
  save: (invoiceId: string) => Promise<void>;
};

export async function persistInvoice(
  writer: InvoiceWriter,
  invoiceId: string,
): Promise<void> {
  try {
    await writer.save(invoiceId);
  } catch (error) {
  }
  console.info("Invoice persisted", invoiceId);
}
