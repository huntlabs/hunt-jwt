module hunt.jwt.Jwt;

import hunt.jwt.Base64Codec;
import hunt.jwt.Exceptions;
import hunt.jwt.JwtOpenSSL;
import hunt.jwt.JwtAlgorithm;

import std.json;
import std.base64;
import std.algorithm;
import std.array : split;


import hunt.logging;


/**
  simple version that accepts only strings as values for payload and header fields
*/
string encode(string[string] payload, string key, JwtAlgorithm algo = JwtAlgorithm.HS256, 
		string[string] header_fields = null) {
	JSONValue jsonHeader = header_fields;
	JSONValue jsonPayload = payload;

	return encode(jsonPayload, key, algo, jsonHeader);
}

/**
  full version that accepts JSONValue tree as payload and header fields
*/
string encode(ref JSONValue payload, string key, JwtAlgorithm algo = JwtAlgorithm.HS256, 
		JSONValue header_fields = null) {
	return encode(cast(ubyte[])payload.toString(), key, algo, header_fields);
}

/**
  full version that accepts ubyte[] as payload and JSONValue tree as header fields
*/
string encode(in ubyte[] payload, string key, JwtAlgorithm algo = JwtAlgorithm.HS256, 
		JSONValue header_fields = null) {
	import std.functional : memoize;

	auto getEncodedHeader(JwtAlgorithm algo, JSONValue fields) {
		if(fields.type == JSONType.null_)
			fields = (JSONValue[string]).init;
		fields.object["alg"] = cast(string)algo;
		fields.object["typ"] = "JWT";

		return Base64URLNoPadding.encode(cast(ubyte[])fields.toString()).idup;
	}

	string encodedHeader = memoize!(getEncodedHeader, 64)(algo, header_fields);
	string encodedPayload = Base64URLNoPadding.encode(payload);

	string signingInput = encodedHeader ~ "." ~ encodedPayload;
	string signValue = sign(signingInput, key, algo);

    version(HUNT_JWT_DEBUG) {
		tracef("sign: %(%02X %)", cast(ubyte[])signValue);
	}

	string signature = Base64URLNoPadding.encode(cast(ubyte[])sign(signingInput, key, algo));
	return signingInput ~ "." ~ signature;
}

// string fromDER(string data) {
	
// }

string encode(string payload, string key, JwtAlgorithm algo, 
		string header_fields) {

	string encodedHeader = Base64URLNoPadding.encode(cast(ubyte[])header_fields); // memoize!(getEncodedHeader, 64)(algo, header_fields);
	string encodedPayload = Base64URLNoPadding.encode(cast(ubyte[])payload);

	string signingInput = encodedHeader ~ "." ~ encodedPayload;
	string signature = Base64URLNoPadding.encode(cast(ubyte[])sign(signingInput, key, algo));

	return signingInput ~ "." ~ signature;
}


/**
  simple version that knows which key was used to encode the token
*/
JSONValue decode(string token, string key) {
	return decode(token, (ref _) => key);
}

/**
  full version where the key is provided after decoding the JOSE header
*/
JSONValue decode(string token, string delegate(ref JSONValue jose) lazyKey) {
	import std.algorithm : count;
	import std.conv : to;
	import std.uni : toUpper;

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
	if(!verifySignature(tokenParts[0]~"."~tokenParts[1], tokenParts[2], key, alg))
		throw new VerifyException("Signature is incorrect.");

	JSONValue payload;

	try {
		payload = parseJSON(cast(string)urlsafeB64Decode(tokenParts[1]));
	} catch(JSONException e) {
		// Code coverage has to miss this line because the signature test above throws before this does
		throw new VerifyException("Payload JSON is incorrect.");
	}

	return payload;
}
