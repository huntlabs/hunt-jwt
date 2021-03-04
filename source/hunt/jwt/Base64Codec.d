module hunt.jwt.Base64Codec;

import std.base64;

alias Base64URLNoPadding = Base64Impl!('-', '_', Base64.NoPadding);


/**
 * Encode a string with URL-safe Base64.
 */
string urlsafeB64Encode(string inp) pure nothrow {
	return Base64URLNoPadding.encode(cast(ubyte[])inp);
}

/**
 * Decode a string with URL-safe Base64.
 */
ubyte[] urlsafeB64Decode(string inp) pure {
	return Base64URLNoPadding.decode(inp);
}
