# Synthetic automatic-encryption test

Developer-only test of a one-time browser setup followed by public-key-only document encryption. All keys and passwords used here are disposable public test material. Do not enter actual passwords or personal documents.

The page does not enroll a real user, register a key, save credentials in browser storage, or modify existing protected strategy pages. A generated synthetic key lasts only in the current page. Its test backup is displayed intentionally and protected only by the displayed public demo password.

Crypto: jose 6.2.12, standard JWE RSA-OAEP-256/A256GCM; WebCrypto password-wrapped PKCS8 test backup. Three structured text tabs are rendered without executing HTML. Public-key fingerprints and allowed formats are checked. Production enrollment and storage require a separate explicit approval and code review.

Test flow: generate synthetic key, send only the public JSON to the Node test encryptor, paste its JWE, unlock, then add another document with the same public key without repeating setup or entering a password at encryption time. Use Lock to clear the in-memory unlock session. Restore fields accept only test-format data.

No operational strategy is migrated by this page. Existing URLs and legacy Staticrypt pages are unchanged.
