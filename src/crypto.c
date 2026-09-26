#include "rakutenai/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#endif

void rakutenai_base64url_encode(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, j = 0;
    while (i < in_len && j + 4 < out_max) {
        size_t rem = in_len - i;
        uint32_t a = in[i++];
        uint32_t b = (rem > 1) ? in[i++] : 0;
        uint32_t c = (rem > 2) ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = tbl[(triple >> 18) & 0x3F];
        out[j++] = tbl[(triple >> 12) & 0x3F];
        if (rem > 1) out[j++] = tbl[(triple >> 6) & 0x3F];
        if (rem > 2) out[j++] = tbl[triple & 0x3F];
    }
    out[j] = '\0';
}

void rakutenai_generate_uuid(char* out, size_t max_len) {
    unsigned char b[16];
#ifdef _WIN32
    BCryptGenRandom(NULL, b, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    RAND_bytes(b, 16);
#endif
    b[6] = (b[6] & 0x0F) | 0x40; /* v4 */
    b[8] = (b[8] & 0x3F) | 0x80; /* variant */
    snprintf(out, max_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

void rakutenai_generate_device_id(char* out, size_t max_len) {
    static const char alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char uuid[40];
    rakutenai_generate_uuid(uuid, sizeof(uuid));

    unsigned char rnd[6];
#ifdef _WIN32
    BCryptGenRandom(NULL, rnd, 6, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    RAND_bytes(rnd, 6);
#endif
    char suffix[7];
    for (int i = 0; i < 6; ++i) {
        suffix[i] = alphanum[rnd[i] % 36];
    }
    suffix[6] = '\0';
    snprintf(out, max_len, "%s-%s", uuid, suffix);
}

void rakutenai_hmac_sha256(const char* message, const char* secret, char* out, size_t out_max) {
    unsigned char hash[32];
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status >= 0) {
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PBYTE)secret, (ULONG)strlen(secret), 0);
        if (status >= 0) {
            status = BCryptHashData(hHash, (PBYTE)message, (ULONG)strlen(message), 0);
            if (status >= 0) {
                BCryptFinishHash(hHash, hash, 32, 0);
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
#else
    unsigned int len = 32;
    HMAC(EVP_sha256(), secret, strlen(secret), (const unsigned char*)message, strlen(message), hash, &len);
#endif
    rakutenai_base64url_encode(hash, 32, out, out_max);
}

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
) {
    time_t now = time(NULL);
    snprintf(out_ts, ts_len, "%lld", (long long)now);
    rakutenai_generate_uuid(out_nonce, nonce_len);

    char raw[2048];
    snprintf(raw, sizeof(raw), "%s%s%s%s%s", method, endpoint, sorted_params ? sorted_params : "", out_ts, out_nonce);
    rakutenai_hmac_sha256(raw, RAKUTENAI_SECRET_KEY, out_sig, sig_len);
}

bool rakutenai_json_extract_string(const char* json, const char* key, char* out, size_t out_len) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char* pos = strstr(json, pattern);
    if (!pos) return false;
    pos += strlen(pattern);
    const char* end = strchr(pos, '\"');
    if (!end) return false;
    size_t len = (size_t)(end - pos);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, pos, len);
    out[len] = '\0';
    return true;
}

bool rakutenai_json_extract_uint64(const char* json, const char* key, uint64_t* out) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char* pos = strstr(json, pattern);
    if (!pos) return false;
    pos += strlen(pattern);
    *out = (uint64_t)strtoull(pos, NULL, 10);
    return true;
}
