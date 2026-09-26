#ifndef RAKUTENAI_CRYPTO_H
#define RAKUTENAI_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

void rakutenai_base64url_encode(const unsigned char* in, size_t in_len, char* out, size_t out_max);
void rakutenai_generate_uuid(char* out, size_t max_len);
void rakutenai_generate_device_id(char* out, size_t max_len);
void rakutenai_hmac_sha256(const char* message, const char* secret, char* out, size_t out_max);
void rakutenai_get_signed_headers(
    const char* method,
    const char* endpoint,
    const char* sorted_params,
    char* out_ts,
    size_t ts_len,
    char* out_nonce,
    size_t nonce_len,
    char* out_sig,
    size_t sig_len
);

bool rakutenai_json_extract_string(const char* json, const char* key, char* out, size_t out_len);
bool rakutenai_json_extract_uint64(const char* json, const char* key, uint64_t* out);

#ifdef __cplusplus
}
#endif

#endif /* RAKUTENAI_CRYPTO_H */
