These test-only fixtures are a self-signed P-256 certificate for DNS name
"localhost" and its unencrypted PKCS#8 private key. They are not product
credentials.

To regenerate outside this workspace:

1. Create a throwaway Rust binary crate.
2. Add exact dependencies base64 0.22.1 and rcgen 0.14.5 with default features
   disabled and the ring feature enabled.
3. Call rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).
4. Base64 STANDARD-encode certified.cert.der() into localhost-cert.der.b64.
5. Base64 STANDARD-encode certified.signing_key.serialize_der() into
   localhost-key.der.b64.
6. Delete the throwaway crate. Do not add rcgen to this workspace.
