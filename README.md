<a href="https://code.dlang.org/packages/jwt" title="Go to jwt"><img src="https://img.shields.io/dub/v/jwt.svg" alt="Dub version"></a>

# JWT

A Simple D implementation of JSON Web Tokens. It's forked from https://github.com/zolamk/jwt.

# Supported Algorithms
- none
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- ES256
- ES384
- ES512


#### This library uses [semantic versioning 2.0.0][3]

# What's New
- added support for `arrays` and `objects` in claims
- removed `verify` function that doesn't take algorithm type, see why [here][4]
- changed `verify` function to take an array of algorithms to support multiple algorithms
- renamed `InvalidSignature` to `InvalidSignatureException`

# How To Use
## Encoding

    import jwt.jwt;
    import jwt.algorithms;
    import std.json;

    void main() {

        JSONValue user = ["id": JSONValue(60119), "uri": JSONValue("https://api.we.are/60119")];

        JwtToken token = new JwtToken(JwtAlgorithm.HS512);

        token.claims.exp = Clock.currTime.toUnixTime();

        token.claims.set("user", user);

        token.claims.set("data", [JSONValue("zm"), JSONValue(58718)]);

        string encodedToken = token.encode("supersecret");

        // work with the encoded token

    }

## Verifying

    import jwt.jwt;
    import jwt.exceptions;
    import jwt.algorithms;

    void main() {

        // get encoded token from header or ...

        try {

            JwtToken token = JwtToken.verify(encodedToken, "supersecret");

            writeln(token.claims.getInt("id"));

            JSONValue user = token.claims.getObject("user");

            JSONValue[] a = token.claims.getArray("data");

            long userID = user["id"].integer();

            string uri = user["uri"].str();

            writeln(userID);

            writeln(uri);

            writeln(a[0].str());

            writeln(a[1].integer());

        } catch (InvalidAlgorithmException e) {

            writeln("token has an invalid algorithm");

        } catch (InvalidSignatureException e) {

            writeln("This token has been tampered with");

        } catch (NotBeforeException e) {

            writeln("Token is not valid yet");

        } catch (ExpiredException e) {

            writeln("Token has expired");

        }

    }

## Encoding without signature


    import jwt.jwt;
    import jwt.algorithms;

    void main() {

        JwtToken token = new JwtToken(JwtAlgorithm.NONE);

        token.claims.exp = Clock.currTime.toUnixTime();

        token.claims.set("id", 60119);

        string encodedToken = token.encode();

        // work with the encoded token

    }

## Verifying without signature

    import jwt.jwt;
    import jwt.exceptions;
    import jwt.algorithms;

    void main() {

        // get encoded token from header or ...

        try {

            JwtToken token = JwtToken.verify(encodedToken);

            writeln(token.claims.getInt("id"));

        } catch (NotBeforeException e) {

            writeln("Token is not valid yet");

        } catch (ExpiredException e) {

            writeln("Token has expired");

        }

    }

# Limitations

- ##### Since Phobos doesn't(hopefully yet) support RSA algorithms this library only provides HMAC signing.

# Note
this library uses code and ideas from [jwtd][1] and [jwt-go][2]

[1]: https://github.com/olehlong/jwtd
[2]: https://github.com/dgrijalva/jwt-go
[3]: http://semver.org
[4]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
