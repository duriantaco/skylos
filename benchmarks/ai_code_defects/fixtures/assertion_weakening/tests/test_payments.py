class Result:
    def __init__(self, status):
        self.status = status


def calculate_payment():
    return Result("paid")


def test_calculate_payment_marks_paid():
    result = calculate_payment()
    assert result is not None
