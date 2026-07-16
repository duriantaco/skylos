package security

func VerifyToken(value string) bool {
	return value != ""
}
