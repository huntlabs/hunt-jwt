module hunt.jwt.JwtToken;

import hunt.jwt.Base64Codec;
import hunt.jwt.Claims;
import hunt.jwt.Component;
import hunt.jwt.Exceptions;
import hunt.jwt.Header;
import hunt.jwt.Jwt;
import hunt.jwt.JwtAlgorithm;
import hunt.jwt.JwtOpenSSL;

import std.conv;
import std.datetime;
import std.json;
import std.string;

import hunt.logging;


/**
* represents a token
*/
class JwtToken {

private {
    Claims _claims;
    Header _header;

    this(Claims claims, Header header) {
        this._claims = claims;
        this._header = header;
    }

    @property string data() {
        return this.header.base64 ~ "." ~ this.claims.base64;
    }
}

    this(in JwtAlgorithm alg, in string typ = "JWT") {
        this._claims = new Claims();
        this._header = new Header(alg, typ);
    }

    @property Claims claims() {
        return this._claims;
    }

    @property Header header() {
        return this._header;
    }

    /**
    * used to get the signature of the token
    * Parmas:
    *       secret = the secret key used to sign the token
    * Returns: the signature of the token
    */
    string signature(string secret) {
        return Base64URLNoPadding.encode(cast(ubyte[])sign(this.data, secret, this.header.alg));

    }

    /**
    * encodes the token
    * Params:
    *       secret = the secret key used to sign the token
    *Returns: base64 representation of the token including signature
    */
    string encode(string secret) {
        if ((this.claims.exp != ulong.init && this.claims.iat != ulong.init) && this.claims.exp < this.claims.iat) {
            throw new ExpiredException("Token has already expired");
        }

        if ((this.claims.exp != ulong.init && this.claims.nbf != ulong.init) && this.claims.exp < this.claims.nbf) {
            throw new ExpiresBeforeValidException("Token will expire before it becomes valid");
        }

        string token = this.data ~ "." ~ this.signature(secret);

        version(HUNT_AUTH_DEBUG) {
            import std.stdio;
            writeln("secret: %s, token: %s", secret, token);
        }

        return token;

    }
    ///
    unittest {
        JwtToken token = new JwtToken(JwtAlgorithm.HS512);

        long now = Clock.currTime.toUnixTime();

        string secret = "super_secret";
        token.claims.exp = now - 3600;

        assertThrown!ExpiredException(token.encode(secret));

        token.claims.exp = now + 3600;
        token.claims.nbf = now + 7200;

        assertThrown!ExpiresBeforeValidException(token.encode(secret));
    }

    /**
    * overload of the encode(string secret) function to simplify encoding of token without algorithm none
    * Returns: base64 representation of the token
    */
    string encode() {
        assert(this.header.alg == JwtAlgorithm.NONE);
        return this.encode("");
    }


    static JwtToken decode(string token, string delegate(ref JSONValue jose) lazyKey) {
        import std.algorithm : count;
        import std.conv : to;
        import std.uni : toUpper;

        version(HUNT_JWT_DEBUG) {
            tracef("token: %s", token);
        }

        if(count(token, ".") != 2)
            throw new VerifyException("Token is incorrect.");

        string[] tokenParts = split(token, ".");

        JSONValue header;
        try {
            header = parseJSON(cast(string)urlsafeB64Decode(tokenParts[0]));
        } catch(Exception e) {
            throw new VerifyException("Header is incorrect.");
        }

        JwtAlgorithm alg;
        try {
            // toUpper for none
            alg = to!(JwtAlgorithm)(toUpper(header["alg"].str()));
        } catch(Exception e) {
            throw new VerifyException("Algorithm is incorrect.");
        }

        if (auto typ = ("typ" in header)) {
            string typ_str = typ.str();
            if(typ_str && typ_str != "JWT")
                throw new VerifyException("Type is incorrect.");
        }

        const key = lazyKey(header);
        if(!key.empty() && !verifySignature(tokenParts[0]~"."~tokenParts[1], tokenParts[2], key, alg))
            throw new VerifyException("Signature is incorrect.");

        JSONValue payload;

        try {
            payload = parseJSON(cast(string)urlsafeB64Decode(tokenParts[1]));
        } catch(JSONException e) {
            // Code coverage has to miss this line because the signature test above throws before this does
            throw new VerifyException("Payload JSON is incorrect.");
        }

        
        Header h = new Header(header);
        Claims claims = new Claims(payload);

        return new JwtToken(claims, h);
    }

    static JwtToken decode(string encodedToken, string key="") {
        return decode(encodedToken, (ref _) => key);	
    }

    static bool verify(string token, string key) {
        import std.algorithm : count;
        import std.conv : to;
        import std.uni : toUpper;

        if(count(token, ".") != 2)
            throw new VerifyException("Token is incorrect.");

        string[] tokenParts = split(token, ".");

        string decHeader = cast(string)urlsafeB64Decode(tokenParts[0]);
        JSONValue header = parseJSON(decHeader);

        JwtAlgorithm alg;
        try {
            // toUpper for none
            alg = to!(JwtAlgorithm)(toUpper(header["alg"].str()));
        } catch(Exception e) {
            throw new VerifyException("Algorithm is incorrect.");
        }

        if (auto typ = ("typ" in header)) {
            string typ_str = typ.str();
            if(typ_str && typ_str != "JWT")
                throw new VerifyException("Type is incorrect.");
        }

        return verifySignature(tokenParts[0]~"."~tokenParts[1], tokenParts[2], key, alg);
    }
}


alias verify = JwtToken.verify;
alias decode = JwtToken.decode;

deprecated("Using JwtToken instead.")
alias Token = JwtToken;