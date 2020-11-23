module hunt.jwt.Header;

import hunt.jwt.Base64Codec;
import hunt.jwt.Component;
import hunt.jwt.JwtAlgorithm;

import std.conv;
import std.json;
import std.string;

/**
 * 
 */
class Header : Component {

    JwtAlgorithm alg;
    string typ;

    this(in JwtAlgorithm alg, in string typ) {
        this.alg = alg;
        this.typ = typ;
    }

    this(in JSONValue headers) {
        try {
            this.alg = to!(JwtAlgorithm)(toUpper(headers["alg"].str()));

        } catch (Exception e) {
            throw new Exception(alg ~ " algorithm is not supported!");

        }

        this.typ = headers["typ"].str();

    }

    @property override string json() {
        JSONValue headers = ["alg": cast(string)this.alg, "typ": this.typ];

        return headers.toString();

    }
}
