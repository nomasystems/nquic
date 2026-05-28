-module(nquic_crypto).

-moduledoc """
QUIC payload protection using AEAD (RFC 9001 Section 5).

Handles AES-128-GCM and ChaCha20-Poly1305 encryption and decryption
of QUIC packet payloads. Nonces are constructed by XORing the IV with
the packet number.
""".

-export([constant_time_equal/2, decrypt/6, encrypt/6]).

-doc """
Constant-time equality for binaries.

Use for any security-sensitive comparison (tokens, MACs, reset tokens)
to avoid revealing length or content through timing.

Returns `false` immediately on length mismatch, which leaks length but
not content. Callers that must also hide length should pad the inputs
to a fixed size before comparing.
""".
-spec constant_time_equal(binary(), binary()) -> boolean().
constant_time_equal(A, B) when byte_size(A) =:= byte_size(B) ->
    crypto:hash_equals(A, B);
constant_time_equal(_, _) ->
    false.

-doc "Decrypt a QUIC packet payload with AEAD. Returns plaintext or `{error, decrypt_failed}`.".
-spec decrypt(
    aes_128_gcm | chacha20_poly1305, binary(), binary(), nquic_packet_number:t(), binary(), binary()
) ->
    binary() | {error, term()}.
decrypt(Cipher, Key, IV, PN, AAD, CiphertextAndTag) ->
    Nonce = make_nonce(IV, PN),
    TagLen = 16,
    Size = byte_size(CiphertextAndTag) - TagLen,
    <<Ciphertext:Size/binary, Tag:TagLen/binary>> = CiphertextAndTag,
    case crypto:crypto_one_time_aead(Cipher, Key, Nonce, Ciphertext, AAD, Tag, false) of
        error -> {error, decrypt_failed};
        Plaintext -> Plaintext
    end.

-doc "Encrypt a QUIC packet payload with AEAD.".
-spec encrypt(
    aes_128_gcm | chacha20_poly1305, binary(), binary(), nquic_packet_number:t(), iodata(), iodata()
) ->
    {binary(), binary()}.
encrypt(Cipher, Key, IV, PN, AAD, Plaintext) ->
    Nonce = make_nonce(IV, PN),
    crypto:crypto_one_time_aead(Cipher, Key, Nonce, Plaintext, AAD, true).

-spec make_nonce(<<_:96>>, nquic_packet_number:t()) -> <<_:96>>.
make_nonce(<<IV0:32, IV1:64>>, PN) ->
    <<IV0:32, (IV1 bxor PN):64>>.
