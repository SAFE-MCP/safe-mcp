# DPoP Verify (Language-agnostic Pseudo)

input: request(method, url, headers), access_token

proof = parse_jwt(headers["DPoP"])
require proof.header.typ == "dpop+jwt"
require proof.claims.htm == request.method
require proof.claims.htu == canonicalize(request.url)
require now - proof.claims.iat <= 300  // 5 min
require replay_cache.add_if_new(proof.claims.jti)  // false => replay

// verify DPoP signature
pubkey = proof.header.jwk
require verify_signature(proof, pubkey)

// compute thumbprint of pubkey (RFC 7638)
dpop_jkt = sha256_jwk_thumbprint(pubkey)

// bind access token to DPoP key
token = decode_jwt(access_token)
require token.cnf.jkt exists
require token.cnf.jkt == dpop_jkt

emit_telemetry({
  trace_id, aud: token.aud, jti: token.jti,
  dpop_jkt, dpop_jti: proof.claims.jti, dpop_result: "success",
  tool, result: "success"
})

forward_request()
