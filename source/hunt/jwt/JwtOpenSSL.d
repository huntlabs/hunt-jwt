module hunt.jwt.JwtOpenSSL;

import deimos.openssl.ssl;
import deimos.openssl.pem;
import deimos.openssl.rsa;
import deimos.openssl.hmac;
import deimos.openssl.err;

import hunt.jwt.Exceptions;
import hunt.jwt.JwtAlgorithm;

import hunt.logging;

import std.conv;
import std.range;

import core.stdc.stdlib : alloca;

string sign(string msg, string key, JwtAlgorithm algo = JwtAlgorithm.HS256) {
    ubyte[] sign;

    void sign_hs(const(EVP_MD)* evp, uint signLen) {
        sign = new ubyte[signLen];

        HMAC_CTX ctx;
        scope(exit) HMAC_CTX_reset(&ctx);
        HMAC_CTX_reset(&ctx);
       
        if(0 == HMAC_Init_ex(&ctx, key.ptr, cast(int)key.length, evp, null)) {
            throw new Exception("Can't initialize HMAC context.");
        }
        if(0 == HMAC_Update(&ctx, cast(const(ubyte)*)msg.ptr, cast(ulong)msg.length)) {
            throw new Exception("Can't update HMAC.");
        }
        if(0 == HMAC_Final(&ctx, cast(ubyte*)sign.ptr, &signLen)) {
            throw new Exception("Can't finalize HMAC.");
        }
    }


version(HUNT_JWT_DEBUG) {
    trace("msg: ", msg);
    trace("key: ", key);
    trace("algo: ", algo);
}

    switch(algo) {
        case JwtAlgorithm.NONE: {
            break;
        }
        case JwtAlgorithm.HS256: {
            sign_hs(EVP_sha256(), SHA256_DIGEST_LENGTH);
            break;
        }
        case JwtAlgorithm.HS384: {
            sign_hs(EVP_sha384(), SHA384_DIGEST_LENGTH);
            break;
        }
        case JwtAlgorithm.HS512: {
            sign_hs(EVP_sha512(), SHA512_DIGEST_LENGTH);
            break;
        }

        /* RSA */
        case JwtAlgorithm.RS256: {
            const(EVP_MD) *alg = EVP_sha256();
            sign = signShaPem(alg, EVP_PKEY_RSA, key, msg);
            break;
        }
        case JwtAlgorithm.RS384: {
            const(EVP_MD) *alg = EVP_sha384();
            sign = signShaPem(alg, EVP_PKEY_RSA, key, msg);
            break;
        }
        case JwtAlgorithm.RS512: {
            const(EVP_MD) *alg = EVP_sha512();
            sign = signShaPem(alg, EVP_PKEY_RSA, key, msg);
            break;
        }

        /* ECC */
        case JwtAlgorithm.ES256: {
            const(EVP_MD) *alg = EVP_sha256();
            sign = signShaPem(alg, EVP_PKEY_EC, key, msg);
            break;
        }
        case JwtAlgorithm.ES384: {
            const(EVP_MD) *alg = EVP_sha384();
            sign = signShaPem(alg, EVP_PKEY_EC, key, msg);
            break;
        }
        case JwtAlgorithm.ES512: {
            const(EVP_MD) *alg = EVP_sha512();
            sign = signShaPem(alg, EVP_PKEY_EC, key, msg);
            break;
        }

        default:
            throw new SignException("Wrong algorithm: " ~ to!string(algo));
    }

    return cast(string)sign;
}

// Ported from https://github.com/benmcollins/libjwt/blob/master/libjwt/jwt-openssl.c
private static ubyte[] signShaPem(const(EVP_MD) *alg, int type, string key, string msg) {
    BIO * bufkey = BIO_new_mem_buf(cast(void*)key.ptr, cast(int)key.length);
    if(bufkey is null) {
        throw new Exception("Can't load the private key.");
    }
    scope(exit) BIO_free(bufkey);

	/* This uses OpenSSL's default passphrase callback if needed. The
	 * library caller can override this in many ways, all of which are
	 * outside of the scope of LibJWT and this is documented in jwt.h. */
	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bufkey, null, null, null);
	if (pkey is null)
        throw new Exception("Invalid argument");
    scope(exit) EVP_PKEY_free(pkey);

	int pkey_type = EVP_PKEY_id(pkey);
	if (pkey_type != type)
        throw new Exception("Invalid argument");

	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	if (mdctx is null)
        throw new Exception("Out of memory");
    scope(exit) EVP_MD_CTX_destroy(mdctx);

	/* Initialize the DigestSign operation using alg */
	if (EVP_DigestSignInit(mdctx, null, alg, null, pkey) != 1)
        throw new Exception("Invalid argument");

	/* Call update with the message */
	if (EVP_DigestSignUpdate(mdctx, cast(void*)msg.ptr, msg.length) != 1)
        throw new Exception("Invalid argument");

	/* First, call EVP_DigestSignFinal with a null sig parameter to get length
	 * of sig. Length is returned in slen */
    size_t slen;
	if (EVP_DigestSignFinal(mdctx, null, &slen) != 1)
        throw new Exception("Invalid argument");

	/* Allocate memory for signature based on returned size */
    // FIXME: Needing refactor or cleanup -@zhangxueping at 2021-03-03T19:38:11+08:00
    // Crashed
	// ubyte[] sig = new ubyte[slen];
    ubyte* sig = cast(ubyte*)alloca(slen);

	/* Get the signature */
	if (EVP_DigestSignFinal(mdctx, sig, &slen) != 1)
        throw new Exception("Invalid argument");

    ubyte[] resultSig;

	if (pkey_type != EVP_PKEY_EC) {
        resultSig = sig[0..slen].dup;
	} else {
		uint degree, bn_len, r_len, s_len, buf_len;

		/* For EC we need to convert to a raw format of R/S. */

		/* Get the actual ec_key */
		EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
		if (ec_key is null)
            throw new Exception("Out of memory");

		degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

		EC_KEY_free(ec_key);

		/* Get the sig from the DER encoded version. */
        version(HUNT_JWT_DEBUG) {
            infof("slen: %d, sig: %(%02X %)", slen, sig[0..slen]);
        }

        // FIXME: Needing refactor or cleanup -@zhangxueping at 2021-03-03T19:39:16+08:00
        // Crashed here
        // ECDSA_SIG *ec_sig = d2i_ECDSA_SIG(null, cast(const(ubyte) **)sig.ptr, cast(long)slen);
		ECDSA_SIG *ec_sig = d2i_ECDSA_SIG(null, cast(const(ubyte) **)&sig, cast(long)slen);
		if (ec_sig is null)
            throw new Exception("Can't decode ECDSA signature.");
        scope(exit) ECDSA_SIG_free(ec_sig);
            
        // version(HUNT_JWT_DEBUG) {
        //     tracef("slen: %d, sig: %(%02X %)", slen, sig[0..slen]);
        // }

        BIGNUM *ec_sig_r;
        BIGNUM *ec_sig_s;
		ECDSA_SIG_get0(ec_sig, &ec_sig_r, &ec_sig_s);
		r_len = BN_num_bytes(ec_sig_r);
		s_len = BN_num_bytes(ec_sig_s);
		bn_len = (degree + 7) / 8;
		if ((r_len > bn_len) || (s_len > bn_len))
            throw new Exception("Invalid argument");

		buf_len = 2 * bn_len;
        ubyte[] raw_buf = new ubyte[buf_len];

		/* Pad the bignums with leading zeroes. */
		// memset(raw_buf, 0, buf_len);
		BN_bn2bin(ec_sig_r, raw_buf.ptr + bn_len - r_len);
		BN_bn2bin(ec_sig_s, raw_buf.ptr + buf_len - s_len);

        resultSig = raw_buf;
	}

    version(HUNT_JWT_DEBUG) {
        tracef("%d, buffer: %(%02X %)", resultSig.length, resultSig);
    }

    return resultSig;
}


bool verifySignature(string head, string signature, string key, JwtAlgorithm algo = JwtAlgorithm.HS256) {
    import hunt.jwt.Base64Codec;

    version(HUNT_JWT_DEBUG) {
        infof("signature： %s", signature);
    }

    ubyte[] decodedSign = cast(ubyte[])urlsafeB64Decode(signature);

    bool verify_rs(ubyte* hash, int type, uint len, uint signLen) {
        RSA* rsa_public = RSA_new();
        scope(exit) RSA_free(rsa_public);

        BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
        if(bpo is null)
            throw new Exception("Can't load key to the BIO.");
        scope(exit) BIO_free(bpo);

        RSA* rsa = PEM_read_bio_RSA_PUBKEY(bpo, &rsa_public, null, null);
        if(rsa is null) {
            throw new Exception("Can't create RSA key.");
        }

        // ubyte[] sign = cast(ubyte[])signature;
        int ret = RSA_verify(type, hash, signLen, decodedSign.ptr, len, rsa_public);
        return ret == 1;
    }


    switch(algo) {
        case JwtAlgorithm.NONE: {
            return key.length == 0;
        }
        case JwtAlgorithm.HS256:
        case JwtAlgorithm.HS384:
        case JwtAlgorithm.HS512: {
            return decodedSign == cast(ubyte[])sign(head, key, algo);
        }

        /* RSA */
        case JwtAlgorithm.RS256: {
            const(EVP_MD) *alg = EVP_sha256();
            return verifyShaPem(alg, EVP_PKEY_RSA, head, decodedSign, key);
        }
        case JwtAlgorithm.RS384: {
            const(EVP_MD) *alg = EVP_sha384();
            return verifyShaPem(alg, EVP_PKEY_RSA, head, decodedSign, key);
        }
        case JwtAlgorithm.RS512: {
            const(EVP_MD) *alg = EVP_sha512();
            return verifyShaPem(alg, EVP_PKEY_RSA, head, decodedSign, key);
        }

        /* ECC */
        case JwtAlgorithm.ES256: {
            const(EVP_MD) *alg = EVP_sha256();
            return verifyShaPem(alg, EVP_PKEY_EC, head, decodedSign, key);

            // ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
            // SHA256(cast(const(ubyte)*)head.ptr, head.length, hash.ptr);
            // return verify_es(NID_secp256k1, hash.ptr, SHA256_DIGEST_LENGTH );
        }
        case JwtAlgorithm.ES384: {
            const(EVP_MD) *alg = EVP_sha384();
            return verifyShaPem(alg, EVP_PKEY_EC, head, decodedSign, key);
        }
        case JwtAlgorithm.ES512: {
            const(EVP_MD) *alg = EVP_sha512();
            return verifyShaPem(alg, EVP_PKEY_EC, head, decodedSign, key);
        }

        default:
            throw new VerifyException("Wrong algorithm.");
    }
}

private bool verifyShaPem(const(EVP_MD) *alg, int type, string head, const(ubyte)[] sig, string key) {
    version(HUNT_JWT_DEBUG) {
        tracef("head: %s", head);
        tracef("sig: %(%02X %)", sig);
    }

    int slen = cast(int)sig.length;

	// sig = jwt_b64_decode(sig_b64, &slen);
	if (sig.empty()) {
        version(HUNT_JWT_DEBUG) warning("Invalid argument");
        return false;
    }

	BIO *bufkey = BIO_new_mem_buf(cast(void*)key.ptr, cast(int)key.length);
	if (bufkey is null) {
        version(HUNT_JWT_DEBUG) warning("Out of memory");
        return false;
    }

    scope(exit) BIO_free(bufkey);

	/* This uses OpenSSL's default passphrase callback if needed. The
	 * library caller can override this in many ways, all of which are
	 * outside of the scope of LibJWT and this is documented in jwt.h. */
	EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bufkey, null, null, null);
	if (pkey is null) {
        version(HUNT_JWT_DEBUG) warning("Invalid argument");
        return false;
    }
    scope(exit) EVP_PKEY_free(pkey);

	int pkey_type = EVP_PKEY_id(pkey);
	if (pkey_type != type) {
        version(HUNT_JWT_DEBUG) warning("Invalid argument");
        return false;
    }

	/* Convert EC sigs back to ASN1. */
	if (pkey_type == EVP_PKEY_EC) {
		uint degree, bn_len;
		EC_KEY *ec_key;

		ECDSA_SIG *ec_sig = ECDSA_SIG_new();
		if (ec_sig is null) {
            version(HUNT_JWT_DEBUG) warning("Out of memory");
            return false;
        }
        scope(exit) ECDSA_SIG_free(ec_sig);

		/* Get the actual ec_key */
		ec_key = EVP_PKEY_get1_EC_KEY(pkey);
		if (ec_key is null) {
            version(HUNT_JWT_DEBUG) warning("Out of memory");
            return false;
        }

		degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

		EC_KEY_free(ec_key);

		bn_len = (degree + 7) / 8;
		if ((bn_len * 2) != slen) {
            version(HUNT_JWT_DEBUG) warning("Invalid argument");
            return false;
        }

		BIGNUM *ec_sig_r = BN_bin2bn(cast(const(ubyte)*)sig.ptr, bn_len, null);
		BIGNUM *ec_sig_s = BN_bin2bn(cast(const(ubyte)*)sig.ptr + bn_len, bn_len, null);
		if (ec_sig_r  is null || ec_sig_s is null) {
            version(HUNT_JWT_DEBUG) warning("Invalid argument");
            return false;
        }

		ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s);

		slen = i2d_ECDSA_SIG(ec_sig, null);
		// sig = jwt_malloc(slen);
        ubyte[] tempBuffer = new ubyte[slen];
        ubyte*p = tempBuffer.ptr;
        // ubyte* tempBuffer = cast(ubyte*)alloca(slen);
        // ubyte*p = tempBuffer;
		slen = i2d_ECDSA_SIG(ec_sig, &p);
		if (slen == 0) {
            version(HUNT_JWT_DEBUG) warning("Invalid argument");
            return false;
        }
        sig = tempBuffer;
	}

	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	if (mdctx is null) {
        version(HUNT_JWT_DEBUG) warning("Out of memory");
        return false;
    }
    scope(exit) EVP_MD_CTX_destroy(mdctx);

	/* Initialize the DigestVerify operation using alg */
	if (EVP_DigestVerifyInit(mdctx, null, alg, null, pkey) != 1){
        version(HUNT_JWT_DEBUG) warning("Invalid argument");
        return false;
    }

	/* Call update with the message */
	if (EVP_DigestVerifyUpdate(mdctx, head.ptr, cast(int)head.length) != 1){
        version(HUNT_JWT_DEBUG) warning("Invalid argument");
        return false;
    }

    version(HUNT_JWT_DEBUG) {
        tracef("slen: %d, sig: %(%02X %)", slen, sig);
    }

	/* Now check the sig for validity. */
	if (EVP_DigestVerifyFinal(mdctx, cast(ubyte*)sig.ptr, slen) != 1) {
        version(HUNT_JWT_DEBUG) warning("Invalid argument");
        return false;
    }

	return true;    

}