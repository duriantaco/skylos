type Invoice = {
  id: string;
  status: string;
};

async function loadInvoice(id: string): Promise<Invoice> {
  return { id, status: "open" };
}

export async function reconcileInvoices(
  ids: string[],
  status: string
): Promise<Invoice[]> {
  const invoices: Invoice[] = [];

  if (status === "paid") {
    await markPaid(ids);
  } else if (status === "void") {
    await markVoid(ids);
  } else if (status === "paid") {
    await markPaid(ids);
  }

  for (let index = 0; index < ids.length; index++) {
    invoices.push(await loadInvoice(ids[index]));
  }

  return invoices;
}

async function markPaid(ids: string[]): Promise<void> {
  void ids;
}

async function markVoid(ids: string[]): Promise<void> {
  void ids;
}
