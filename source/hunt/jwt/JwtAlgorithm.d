module hunt.jwt.JwtAlgorithm;


enum JwtAlgorithm : string {
	NONE  = "none",
	HS256 = "HS256",
	HS384 = "HS384",
	HS512 = "HS512",
	RS256 = "RS256",
	RS384 = "RS384",
	RS512 = "RS512",
	ES256 = "ES256",
	ES384 = "ES384",
	ES512 = "ES512"
}

deprecated("Using JwtAlgorithm instead.")
alias JWTAlgorithm = JwtAlgorithm;