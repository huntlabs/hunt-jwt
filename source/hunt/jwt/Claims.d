module hunt.jwt.Claims;

import hunt.jwt.Base64Codec;
import hunt.jwt.Component;
import hunt.jwt.Exceptions;
import hunt.jwt.JwtAlgorithm;

import std.conv;
import std.datetime;
import std.json;
import std.string;

/**
* represents the claims component of a JWT
*/
class Claims : Component {
    private JSONValue data;

    private this(in JSONValue claims) {
        this.data = claims;

    }

    this() {
        this.data = JSONValue(["iat": JSONValue(Clock.currTime.toUnixTime())]);
    }

    void set(T)(string name, T data) {
        static if(is(T == JSONValue)) {
            this.data.object[name] = data;
        } else {
            this.data.object[name] = JSONValue(data);
        }
    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a string representation of the claim if it exists and is a string or an empty string if doesn't exist or is not a string
    */
    string get(string name) {
        try {
            return this.data[name].str();

        } catch (JSONException e) {
            return string.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: an array of JSONValue
    */
    JSONValue[] getArray(string name) {
        try {
            return this.data[name].array();

        } catch (JSONException e) {
            return JSONValue.Store.array.init;

        }

    }


    /**
    * Params:
    *       name = the name of the claim
    * Returns: a JSONValue
    */
    JSONValue[string] getObject(string name) {
        try {
            return this.data[name].object();

        } catch (JSONException e) {
            return JSONValue.Store.object.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a long representation of the claim if it exists and is an
    *          integer or the initial value for long if doesn't exist or is not an integer
    */
    long getInt(string name) {
        try {
            return this.data[name].integer();

        } catch (JSONException e) {
            return long.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a double representation of the claim if it exists and is a
    *          double or the initial value for double if doesn't exist or is not a double
    */
    double getDouble(string name) {
        try {
            return this.data[name].floating();

        } catch (JSONException e) {
            return double.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a boolean representation of the claim if it exists and is a
    *          boolean or the initial value for bool if doesn't exist or is not a boolean
    */
    bool getBool(string name) {
        try {
            return this.data[name].type == JSONType.true_;

        } catch (JSONException e) {
            return bool.init;

        }

    }

    /**
    * Params:
    *       name = the name of the claim
    * Returns: returns a boolean value if the claim exists and is null or
    *          the initial value for bool it it doesn't exist or is not null
    */
    bool isNull(string name) {
        try {
            return this.data[name].isNull();

        } catch (JSONException) {
            return bool.init;

        }

    }

    @property void iss(string s) {
        this.data.object["iss"] = s;
    }


    @property string iss() {
        try {
            return this.data["iss"].str();

        } catch (JSONException e) {
            return "";

        }

    }

    @property void sub(string s) {
        this.data.object["sub"] = s;
    }

    @property string sub() {
        try {
            return this.data["sub"].str();

        } catch (JSONException e) {
            return "";

        }

    }

    @property void aud(string s) {
        this.data.object["aud"] = s;
    }

    @property string aud() {
        try {
            return this.data["aud"].str();

        } catch (JSONException e) {
            return "";

        }

    }

    @property void exp(long n) {
        this.data.object["exp"] = n;
    }

    @property long exp() {
        try {
            return this.data["exp"].integer;

        } catch (JSONException) {
            return 0;

        }

    }

    @property void nbf(long n) {
        this.data.object["nbf"] = n;
    }

    @property long nbf() {
        try {
            return this.data["nbf"].integer;

        } catch (JSONException) {
            return 0;

        }

    }

    @property void iat(long n) {
        this.data.object["iat"] = n;
    }

    @property long iat() {
        try {
            return this.data["iat"].integer;

        } catch (JSONException) {
            return 0;

        }

    }

    @property void jit(string s) {
        this.data.object["jit"] = s;
    }

    @property string jit() {
        try {
            return this.data["jit"].str();

        } catch(JSONException e) {
            return "";

        }

    }

    /**
    * gives json encoded claims
    * Returns: json encoded claims
    */
    @property override string json() {
        return this.data.toString();

    }
}
