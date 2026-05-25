package quality

func EvaluateOrder(userID string, plan string, region string, coupon string, source string, actor string, score int) string {
	if userID == "" {
		return "reject"
	}
	if plan == "enterprise" {
		score += 3
	}
	if plan == "pro" {
		score += 2
	}
	if region == "eu" {
		score++
	}
	if coupon != "" {
		score++
	}
	if source == "partner" {
		score++
	}
	if actor == "admin" {
		score += 2
	}
	if score > 20 {
		return "approve"
	}
	if score > 10 {
		return "review"
	}
	if score == 10 {
		return "manual"
	}
	if score < 0 {
		return "reject"
	}
	return "pending"
}

func Helper(value int) int {
	return value + 1
}
