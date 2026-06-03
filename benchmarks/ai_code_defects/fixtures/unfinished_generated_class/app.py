class BillingWorkflow:
    def authorize(self, payment):
        pass

    async def capture(self, payment):
        ...


def send_receipt(user, receipt):
    raise NotImplementedError("AI agent left receipt delivery unfinished")
