# Crypto inventory - webapp\sample_app.py

CI gate: **PASS**

| Location | Algorithm | Risk | Target | State |
|---|---|---|---|---|
| webapp\sample_app.py:13 hash_password | MD5 | already_deprecated | SHA3-256 | migrated_verified |
| webapp\sample_app.py:17 sign_document | RSA | broken_by_shor | ML-DSA-87 | migrated_verified |
| webapp\sample_app.py:22 derive_shared | ECDH | broken_by_shor | ML-KEM-1024 | migrated_verified |
| webapp\sample_app.py:27 seal_blob | AES-GCM | weakened_by_grover | ChaCha20-Poly1305 | migrated_verified |
| webapp\sample_app.py:31 make_cookie | Fernet | weakened_by_grover | ChaCha20-Poly1305 | migrated_verified |
| webapp\sample_app.py:35 old_encrypt | AES | weakened_by_grover | AES-256-GCM | migrated_verified |
| webapp\sample_app.py:40 tag_message | HMAC-SHA1 | already_deprecated | HMAC-SHA3-256 | migrated_verified |
| webapp\sample_app.py:44 issue_token | RSA | broken_by_shor | ML-DSA-87 | migrated_verified |
| webapp\sample_app.py:48 pq_handshake | KEM | quantum_safe | - | safe |
