class BillingWorkflow:
    def authorize(self, payment) -> bool:
        pass

    async def capture(self, payment) -> str:
        ...


def send_receipt(user, receipt):
    raise NotImplementedError("Implementation pending: receipt delivery")
