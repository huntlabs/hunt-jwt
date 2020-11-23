import std.stdio;

import hunt.jwt;
import hunt.logging.ConsoleLogger;

import std.datetime;
import std.exception;
import std.conv;
import std.json;
import std.format;
    

void main()
{
    // testToken();
    // testHS512();
    testES256();
}

void testToken() {

	string tokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJuYW1lIjoiYWxpY2UiLCJlbWFpbCI6ImFsaWNlQGdtYWlsLmNvbSIsInBob25lX251bWJlciI6IjE4ODAwMDAwMDAxIiwibmJmIjoxNTA5NDY0MzQwLCJleHAiOjE1MTAwNjkxNDAsImlhdCI6MTUwOTQ2NDM0MH0.nV7duR2gWHA3TB9xPhP1WWhDpXRn1GA_k8_zBBirT6g";

    JwtToken tk = JwtToken.decode(tokenString);

    writeln(tk.header.json());
    writeln(tk.claims.json());

    assert(JwtToken.verify(tokenString, "secret"));
}

// HS512
void testHS512() {
    scope(failure) {
        warning("failed");
    }

    scope(success) {
        info("passed");
    }

    string hs_secret = "secret";
    enum FinalToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MDYwMzI4MjQsImxhbmd1YWdlIjoiRCJ9.nIWh2aWLdjA64NWm5P1RO5vG66DKGg8nXAfJ7js3qEV1CoX-BNvXFKvhPJvNby7_ZQTrqHLpCNBWEdtrshxYFQ";
    long iat = 1606032824;
    JSONValue payload = parseJSON(`{"iat":1606032824,"language":"D"}`);

    string hs512Token = encode(payload, hs_secret, JwtAlgorithm.HS512);
    assert(hs512Token == FinalToken);
    assert(JwtToken.verify(hs512Token, hs_secret));    
    
    warning(hs512Token);

    JwtToken token = new JwtToken(JwtAlgorithm.HS512);
    token.claims.set("language", "D");
    token.claims.iat = iat;
    string hs512Token2 = token.encode(hs_secret);
    warning(hs512Token2);
    assert(hs512Token == hs512Token2);

    //

    token = JwtToken.decode(FinalToken, hs_secret);
    string language = token.claims.get("language");
    assert(language == "D");
}


    // ES256
void testES256() {

    scope(failure) {
        warning("failed");
    }

    scope(success) {
        info("passed");
    }

    string es256_public = q"EOS
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEMuSnsWbiIPyfFAIAvlbliPOUnQlibb67
yE6JUqXVaevb8ZorK2HfxfFg9pGVhg3SGuBCbHcJ84WKOX3GSMEwcA==
-----END PUBLIC KEY-----
EOS";


    string es256_private = q"EOS
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIB8cQPtLEF5hOJsom5oVU5dMpgDUR2QYuJTXdtvxezQloAcGBSuBBAAK
oUQDQgAEMuSnsWbiIPyfFAIAvlbliPOUnQlibb67yE6JUqXVaevb8ZorK2HfxfFg
9pGVhg3SGuBCbHcJ84WKOX3GSMEwcA==
-----END EC PRIVATE KEY-----
EOS";

    long iat = 1606032824;
    JSONValue payload = parseJSON(format(`{"iat":%d,"language":"D"}`, iat));

    string es256Token = encode(payload, es256_private, JwtAlgorithm.ES256);
    warning(es256Token);
    // assert(es256Token == Es256FinalToken);
    assert(JwtToken.verify(es256Token, es256_public)); 

    
    string es256Token1 = encode(payload, es256_private, JwtAlgorithm.ES256);
    trace(es256Token1);

    assert(es256Token != es256Token1);
    
    JwtToken token = new JwtToken(JwtAlgorithm.ES256);
    token.claims.set("language", "D");
    token.claims.iat = iat;
    string es256Token2 = token.encode(es256_private);
    warning(es256Token2);
    assert(JwtToken.verify(es256Token2, es256_public)); 


    // 
    token = JwtToken.decode(es256Token2, es256_public);

    string language = token.claims.get("language");
    assert(language == "D");        
}