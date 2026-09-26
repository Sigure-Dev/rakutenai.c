#include "rakutenai.h"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

static const char* BASE_HOST = "ai.rakuten.co.jp";
static const char* SECRET_KEY = "4f0465bfea7761a510dda451ff86a935bf0c8ed6fb37f80441509c64328788c8";

struct rakutenai_thread {
    char id[64];
    rakutenai_user_t user;
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    HINTERNET hWebSocket;
};

/* 高速 Base64URL エンコード (パディングなし、スタック書き込み) */
static void base64url_encode(const unsigned char* in, size_t in_len, char* out, size_t out_max) {
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

/* UUID v4 生成 */
static void generate_uuid(char* out, size_t max_len) {
    unsigned char b[16];
    BCryptGenRandom(NULL, b, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    b[6] = (b[6] & 0x0F) | 0x40; /* version 4 */
    b[8] = (b[8] & 0x3F) | 0x80; /* variant */
    snprintf(out, max_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* Device ID 生成 */
static void generate_device_id(char* out, size_t max_len) {
    static const char alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char uuid[40];
    generate_uuid(uuid, sizeof(uuid));

    unsigned char rnd[6];
    BCryptGenRandom(NULL, rnd, 6, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    char suffix[7];
    for (int i = 0; i < 6; ++i) {
        suffix[i] = alphanum[rnd[i] % 36];
    }
    suffix[6] = '\0';
    snprintf(out, max_len, "%s-%s", uuid, suffix);
}

/* ハードウェアアクセラレーション HMAC-SHA256 署名生成 */
static void calculate_hmac_sha256(const char* message, const char* secret, char* out, size_t out_max) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    unsigned char hash[32];

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
    base64url_encode(hash, 32, out, out_max);
}

/* 署名ヘッダーの生成 */
static void get_signed_headers(const char* method, const char* endpoint, const char* sorted_params, char* out_ts, size_t ts_len, char* out_nonce, size_t nonce_len, char* out_sig, size_t sig_len) {
    time_t now = time(NULL);
    snprintf(out_ts, ts_len, "%lld", (long long)now);
    generate_uuid(out_nonce, nonce_len);

    char raw[2048];
    snprintf(raw, sizeof(raw), "%s%s%s%s%s", method, endpoint, sorted_params ? sorted_params : "", out_ts, out_nonce);
    calculate_hmac_sha256(raw, SECRET_KEY, out_sig, sig_len);
}

/* JSON文字列抽出 */
static bool json_extract_string(const char* json, const char* key, char* out, size_t out_len) {
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

static bool json_extract_int(const char* json, const char* key, uint64_t* out) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char* pos = strstr(json, pattern);
    if (!pos) return false;
    pos += strlen(pattern);
    *out = (uint64_t)strtoull(pos, NULL, 10);
    return true;
}

/* HTTPリクエスト共通 */
static char* http_request(const char* host, const char* path, const char* verb, const wchar_t* w_headers, const void* body, size_t body_len, size_t* out_len) {
    wchar_t whost[256];
    wchar_t wpath[2048];
    wchar_t wverb[16];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 2048);
    MultiByteToWideChar(CP_UTF8, 0, verb, -1, wverb, 16);

    HINTERNET hSession = WinHttpOpen(L"RakutenAI-C/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    HINTERNET hConnect = WinHttpConnect(hSession, whost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return NULL; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wverb, wpath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return NULL; }

    BOOL bRes = WinHttpSendRequest(hRequest, w_headers, (DWORD)wcslen(w_headers), (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);
    if (bRes) bRes = WinHttpReceiveResponse(hRequest, NULL);

    char* resp = NULL;
    size_t total = 0;

    if (bRes) {
        DWORD dwSize = 0, dwRead = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
            char* new_resp = (char*)realloc(resp, total + dwSize + 1);
            if (!new_resp) break;
            resp = new_resp;
            if (WinHttpReadData(hRequest, resp + total, dwSize, &dwRead)) {
                total += dwRead;
            }
        } while (dwSize > 0);
    }

    if (resp) resp[total] = '\0';
    if (out_len) *out_len = total;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

/* User API 実装 */
bool rakutenai_user_create(rakutenai_user_t* out_user) {
    if (!out_user) return false;
    memset(out_user, 0, sizeof(*out_user));
    generate_device_id(out_user->device_id, sizeof(out_user->device_id));

    const char* endpoint = "/api/v2/auth/anonymous";
    char ts[32], nonce[64], sig[128];
    get_signed_headers("GET", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    wchar_t wh[2048];
    swprintf(wh, sizeof(wh)/sizeof(wh[0]),
        L"Content-Type: application/json\r\n"
        L"X-Platform: WEB\r\n"
        L"X-Country-Code: JP\r\n"
        L"Device-ID: %hs\r\n"
        L"X-Timestamp: %hs\r\n"
        L"X-Nonce: %hs\r\n"
        L"X-Signature: %hs\r\n",
        out_user->device_id, ts, nonce, sig);

    char* res = http_request(BASE_HOST, endpoint, "GET", wh, NULL, 0, NULL);
    if (!res) return false;

    bool ok = json_extract_string(res, "accessToken", out_user->access_token, sizeof(out_user->access_token)) &&
              json_extract_string(res, "refreshToken", out_user->refresh_token, sizeof(out_user->refresh_token));

    out_user->expires_at = (int64_t)time(NULL) + 3600;
    free(res);
    return ok;
}

bool rakutenai_user_refresh_token(rakutenai_user_t* user) {
    if (!user) return false;
    const char* endpoint = "/api/v2/auth/refresh";
    char ts[32], nonce[64], sig[128];
    get_signed_headers("POST", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    wchar_t wh[2048];
    swprintf(wh, sizeof(wh)/sizeof(wh[0]),
        L"Content-Type: application/json\r\n"
        L"Authorization: Bearer %hs\r\n"
        L"X-Platform: WEB\r\n"
        L"X-Country-Code: JP\r\n"
        L"Device-ID: %hs\r\n"
        L"X-Timestamp: %hs\r\n"
        L"X-Nonce: %hs\r\n"
        L"X-Signature: %hs\r\n",
        user->access_token, user->device_id, ts, nonce, sig);

    char body[1500];
    snprintf(body, sizeof(body), "{\"refreshToken\":\"%s\"}", user->refresh_token);

    char* res = http_request(BASE_HOST, endpoint, "POST", wh, body, strlen(body), NULL);
    if (!res) return false;

    bool ok = json_extract_string(res, "accessToken", user->access_token, sizeof(user->access_token)) &&
              json_extract_string(res, "refreshToken", user->refresh_token, sizeof(user->refresh_token));
    user->expires_at = (int64_t)time(NULL) + 3600;
    free(res);
    return ok;
}

rakutenai_thread_t* rakutenai_thread_create(
    rakutenai_user_t* user,
    const char* title,
    const char* agent_id_opt,
    const char* shareable_link_id_opt
) {
    if (!user) return NULL;

    const char* endpoint = "/api/v1/thread";
    char ts[32], nonce[64], sig[128];
    get_signed_headers("POST", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    wchar_t wh[2048];
    swprintf(wh, sizeof(wh)/sizeof(wh[0]),
        L"Content-Type: application/json\r\n"
        L"Authorization: Bearer %hs\r\n"
        L"X-Platform: WEB\r\n"
        L"X-Country-Code: JP\r\n"
        L"Device-ID: %hs\r\n"
        L"X-Timestamp: %hs\r\n"
        L"X-Nonce: %hs\r\n"
        L"X-Signature: %hs\r\n",
        user->access_token, user->device_id, ts, nonce, sig);

    const char* aid = agent_id_opt ? agent_id_opt : RAKUTENAI_DEFAULT_AGENT_ID;
    const char* t = title ? title : "新しいスレッド";

    char body[1024];
    if (shareable_link_id_opt) {
        snprintf(body, sizeof(body), "{\"scenarioAgentId\":\"%s\",\"title\":\"%s\",\"shareableLinkId\":\"%s\",\"multipleThreadMode\":true}", aid, t, shareable_link_id_opt);
    } else {
        snprintf(body, sizeof(body), "{\"scenarioAgentId\":\"%s\",\"title\":\"%s\"}", aid, t);
    }

    char* res = http_request(BASE_HOST, endpoint, "POST", wh, body, strlen(body), NULL);
    if (!res) return NULL;

    rakutenai_thread_t* thread = (rakutenai_thread_t*)calloc(1, sizeof(rakutenai_thread_t));
    if (!thread) { free(res); return NULL; }

    thread->user = *user;
    if (!json_extract_string(res, "id", thread->id, sizeof(thread->id))) {
        free(res);
        free(thread);
        return NULL;
    }
    free(res);
    return thread;
}

const char* rakutenai_thread_get_id(const rakutenai_thread_t* thread) {
    return thread ? thread->id : "";
}

rakutenai_thread_t* rakutenai_thread_from_shared(rakutenai_user_t* user, const char* share_id) {
    if (!user || !share_id) return NULL;

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/api/v1/share/%s", share_id);

    char ts[32], nonce[64], sig[128];
    get_signed_headers("GET", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    wchar_t wh[2048];
    swprintf(wh, sizeof(wh)/sizeof(wh[0]),
        L"Authorization: Bearer %hs\r\n"
        L"X-Platform: WEB\r\n"
        L"X-Country-Code: JP\r\n"
        L"Device-ID: %hs\r\n"
        L"X-Timestamp: %hs\r\n"
        L"X-Nonce: %hs\r\n"
        L"X-Signature: %hs\r\n",
        user->access_token, user->device_id, ts, nonce, sig);

    char* res = http_request(BASE_HOST, endpoint, "GET", wh, NULL, 0, NULL);
    if (!res) return NULL;

    char title[256] = "Shared Thread";
    char agent_id[64] = RAKUTENAI_DEFAULT_AGENT_ID;
    json_extract_string(res, "title", title, sizeof(title));
    json_extract_string(res, "scenarioAgentId", agent_id, sizeof(agent_id));
    free(res);

    char fork_title[300];
    snprintf(fork_title, sizeof(fork_title), "Continue: %s", title);

    rakutenai_thread_t* t = rakutenai_thread_create(user, fork_title, agent_id, share_id);
    if (t) {
        rakutenai_thread_connect(t);
    }
    return t;
}

bool rakutenai_thread_connect(rakutenai_thread_t* thread) {
    if (!thread) return false;

    time_t now = time(NULL);
    char ts[32], nonce[64], sig[128];
    snprintf(ts, sizeof(ts), "%lld", (long long)now);
    generate_uuid(nonce, sizeof(nonce));

    /* 署名対象: GET/ws/v1/chataccessToken=...deviceId=...platform=WEBtimestampnonce */
    char sorted[2048];
    snprintf(sorted, sizeof(sorted), "accessToken=%sdeviceId=%splatform=WEB", thread->user.access_token, thread->user.device_id);

    char raw[4096];
    snprintf(raw, sizeof(raw), "GET/ws/v1/chat%s%s%s", sorted, ts, nonce);
    calculate_hmac_sha256(raw, SECRET_KEY, sig, sizeof(sig));

    char path[4096];
    snprintf(path, sizeof(path), "/ws/v1/chat?accessToken=%s&platform=WEB&deviceId=%s&x-timestamp=%s&x-nonce=%s&x-signature=%s",
        thread->user.access_token, thread->user.device_id, ts, nonce, sig);

    wchar_t wpath[4096];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 4096);

    thread->hSession = WinHttpOpen(L"RakutenAI-C/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!thread->hSession) return false;

    thread->hConnect = WinHttpConnect(thread->hSession, L"companion.ai.rakuten.co.jp", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!thread->hConnect) return false;

    thread->hRequest = WinHttpOpenRequest(thread->hConnect, L"GET", wpath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!thread->hRequest) return false;

    if (!WinHttpSetOption(thread->hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) return false;
    if (!WinHttpSendRequest(thread->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) return false;
    if (!WinHttpReceiveResponse(thread->hRequest, NULL)) return false;

    thread->hWebSocket = WinHttpWebSocketCompleteUpgrade(thread->hRequest, 0);
    return (thread->hWebSocket != NULL);
}

static const char* chat_mode_to_string(rakutenai_chat_mode_t m) {
    switch (m) {
        case RAKUTENAI_MODE_USER_INPUT: return "USER_INPUT";
        case RAKUTENAI_MODE_DEEP_THINK: return "DEEP_THINK";
        case RAKUTENAI_MODE_AI_READ: return "AI_READ";
    }
    return "USER_INPUT";
}

bool rakutenai_thread_send_message(
    rakutenai_thread_t* thread,
    const rakutenai_content_t* contents,
    size_t contents_count,
    rakutenai_chat_mode_t mode,
    rakutenai_event_cb callback,
    void* user_data
) {
    if (!thread || !thread->hWebSocket) return false;

    char user_msg_id[40];
    generate_uuid(user_msg_id, sizeof(user_msg_id));
    int64_t now_ms = (int64_t)time(NULL) * 1000;

    char payload[65536];
    size_t offset = snprintf(payload, sizeof(payload),
        "{\"message\":{\"type\":\"CONVERSATION\",\"payload\":{\"action\":\"%s\",\"data\":{\"chatRequestType\":\"%s\",\"role\":\"user\",\"userId\":\"%s\",\"threadId\":\"%s\",\"messageId\":\"%s\",\"language\":\"ja\",\"platform\":\"WEB\",\"timestamp\":%lld,\"contents\":[",
        chat_mode_to_string(mode), chat_mode_to_string(mode), thread->user.device_id, thread->id, user_msg_id, (long long)now_ms);

    for (size_t i = 0; i < contents_count && offset < sizeof(payload) - 256; ++i) {
        if (i > 0) offset += snprintf(payload + offset, sizeof(payload) - offset, ",");
        if (contents[i].type == RAKUTENAI_CONTENT_TEXT) {
            offset += snprintf(payload + offset, sizeof(payload) - offset, "{\"contentType\":\"TEXT\",\"textData\":{\"text\":\"%s\"}}", contents[i].text);
        } else {
            if (contents[i].file.is_image) {
                offset += snprintf(payload + offset, sizeof(payload) - offset, "{\"contentType\":\"INPUT_IMAGE\",\"inputImageData\":{\"src\":\"%s\",\"resourceId\":\"%s\"}}", contents[i].file.file_url, contents[i].file.file_id);
            } else {
                offset += snprintf(payload + offset, sizeof(payload) - offset, "{\"contentType\":\"INPUT_FILE\",\"inputFileData\":{\"src\":\"%s\",\"resourceId\":\"%s\",\"name\":\"%s\"}}", contents[i].file.file_url, contents[i].file.file_id, contents[i].file.file_name);
            }
        }
    }

    snprintf(payload + offset, sizeof(payload) - offset,
        "],\"retry\":false,\"debug\":false,\"timezoneString\":\"Asia/Tokyo\",\"countryCode\":\"JP\",\"city\":\"Nerima\",\"explicitSearch\":\"AUTO\"}},\"metadata\":{\"messageId\":\"%s\",\"timestamp\":%lld}}}",
        user_msg_id, (long long)now_ms);

    DWORD err = WinHttpWebSocketSend(thread->hWebSocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, payload, (DWORD)strlen(payload));
    if (err != ERROR_SUCCESS) return false;

    char recv_buf[65536];
    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType;

    char* accumulator = NULL;
    size_t acc_len = 0;

    while (true) {
        err = WinHttpWebSocketReceive(thread->hWebSocket, recv_buf, sizeof(recv_buf), &bytesRead, &bufType);
        if (err != ERROR_SUCCESS || bufType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            if (callback) {
                rakutenai_event_t ev = { RAKUTENAI_EVENT_DISCONNECTED, NULL, NULL, 0, 0, NULL };
                callback(&ev, user_data);
            }
            break;
        }

        char* new_acc = (char*)realloc(accumulator, acc_len + bytesRead + 1);
        if (!new_acc) break;
        accumulator = new_acc;
        memcpy(accumulator + acc_len, recv_buf, bytesRead);
        acc_len += bytesRead;
        accumulator[acc_len] = '\0';

        if (bufType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            char* msg = accumulator;

            if (strstr(msg, "\"type\":\"ACK\"")) {
                if (callback) {
                    rakutenai_event_t ev = { RAKUTENAI_EVENT_ACK, NULL, NULL, 0, 0, NULL };
                    callback(&ev, user_data);
                }
            } else if (strstr(msg, "\"chatResponseStatus\":\"DONE\"")) {
                if (callback) {
                    rakutenai_event_t ev = { RAKUTENAI_EVENT_DONE, NULL, NULL, 0, 0, NULL };
                    callback(&ev, user_data);
                }
                free(accumulator);
                return true;
            } else if (strstr(msg, "\"action\":\"EVENT\"")) {
                if (strstr(msg, "思考中...")) {
                    if (callback) {
                        rakutenai_event_t ev = { RAKUTENAI_EVENT_REASONING_START, NULL, NULL, 0, 0, NULL };
                        callback(&ev, user_data);
                    }
                }
            } else if (strstr(msg, "\"chatResponseStatus\":\"APPEND\"")) {
                const char* t_pos = strstr(msg, "\"text\":\"");
                if (t_pos) {
                    t_pos += 8;
                    char unescaped[16384];
                    size_t u = 0;
                    while (*t_pos && *t_pos != '\"' && u < sizeof(unescaped) - 1) {
                        if (*t_pos == '\\' && *(t_pos + 1)) {
                            t_pos++;
                            if (*t_pos == 'n') unescaped[u++] = '\n';
                            else if (*t_pos == 'r') unescaped[u++] = '\r';
                            else if (*t_pos == 't') unescaped[u++] = '\t';
                            else if (*t_pos == '\"') unescaped[u++] = '\"';
                            else if (*t_pos == '\\') unescaped[u++] = '\\';
                            else unescaped[u++] = *t_pos;
                        } else {
                            unescaped[u++] = *t_pos;
                        }
                        t_pos++;
                    }
                    unescaped[u] = '\0';

                    rakutenai_event_t ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.type = strstr(msg, "\"contentType\":\"SUMMARY_TEXT\"") ? RAKUTENAI_EVENT_REASONING_DELTA : RAKUTENAI_EVENT_TEXT_DELTA;
                    ev.text = unescaped;
                    if (callback) callback(&ev, user_data);
                }

                if (strstr(msg, "\"contentType\":\"OUTPUT_IMAGE\"")) {
                    char thumb[512], prev[512];
                    if (json_extract_string(msg, "thumbnail", thumb, sizeof(thumb))) {
                        rakutenai_event_t ev = { RAKUTENAI_EVENT_IMAGE_THUMBNAIL, NULL, thumb, 0, 0, NULL };
                        if (callback) callback(&ev, user_data);
                    }
                    if (json_extract_string(msg, "preview", prev, sizeof(prev))) {
                        rakutenai_event_t ev = { RAKUTENAI_EVENT_IMAGE, NULL, prev, 0, 0, NULL };
                        if (callback) callback(&ev, user_data);
                    }
                }

                if (strstr(msg, "\"responseMetricsData\"")) {
                    uint64_t in_tok = 0, out_tok = 0;
                    json_extract_int(msg, "inputTokens", &in_tok);
                    json_extract_int(msg, "outputTokens", &out_tok);
                    rakutenai_event_t ev = { RAKUTENAI_EVENT_USAGE, NULL, NULL, in_tok, out_tok, NULL };
                    if (callback) callback(&ev, user_data);
                }
            }

            free(accumulator);
            accumulator = NULL;
            acc_len = 0;
        }
    }

    if (accumulator) free(accumulator);
    return true;
}

bool rakutenai_user_upload_file(
    rakutenai_user_t* user,
    const uint8_t* file_data,
    size_t file_len,
    const char* filename,
    const char* mime_type,
    bool is_image,
    const char* thread_id_opt,
    rakutenai_uploaded_file_t* out_file
) {
    if (!user || !file_data || !out_file) return false;

    const char* endpoint = "/api/v1/files/upload";
    char ts[32], nonce[64], sig[128];
    get_signed_headers("POST", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    char boundary_uuid[40];
    generate_uuid(boundary_uuid, sizeof(boundary_uuid));
    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----WebKitFormBoundary%s", boundary_uuid);

    char act_thread_id[64];
    if (thread_id_opt && thread_id_opt[0]) {
        snprintf(act_thread_id, sizeof(act_thread_id), "%s", thread_id_opt);
    } else {
        generate_uuid(act_thread_id, sizeof(act_thread_id));
    }

    char head[1024];
    int head_len = snprintf(head, sizeof(head),
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: %s\r\n\r\n",
        boundary, filename, mime_type);

    char tail[1024];
    int tail_len = snprintf(tail, sizeof(tail),
        "\r\n--%s\r\n"
        "Content-Disposition: form-data; name=\"request\"; filename=\"blob\"\r\n"
        "Content-Type: application/json\r\n\r\n"
        "{\"type\":\"%s\",\"agentId\":\"%s\",\"threadId\":\"%s\"}\r\n"
        "--%s--\r\n",
        boundary, is_image ? "VISION_DATA" : "USER_DATA", RAKUTENAI_DEFAULT_AGENT_ID, act_thread_id, boundary);

    size_t body_size = head_len + file_len + tail_len;
    uint8_t* body = (uint8_t*)malloc(body_size);
    if (!body) return false;

    memcpy(body, head, head_len);
    memcpy(body + head_len, file_data, file_len);
    memcpy(body + head_len + file_len, tail, tail_len);

    wchar_t wh[2048];
    swprintf(wh, sizeof(wh)/sizeof(wh[0]),
        L"Content-Type: multipart/form-data; boundary=%hs\r\n"
        L"Authorization: Bearer %hs\r\n"
        L"X-Platform: WEB\r\n"
        L"X-Country-Code: JP\r\n"
        L"Device-ID: %hs\r\n"
        L"X-Timestamp: %hs\r\n"
        L"X-Nonce: %hs\r\n"
        L"X-Signature: %hs\r\n",
        boundary, user->access_token, user->device_id, ts, nonce, sig);

    char* res = http_request(BASE_HOST, endpoint, "POST", wh, body, body_size, NULL);
    free(body);
    if (!res) return false;

    memset(out_file, 0, sizeof(*out_file));
    bool ok = json_extract_string(res, "fileId", out_file->file_id, sizeof(out_file->file_id)) &&
              json_extract_string(res, "fileUrl", out_file->file_url, sizeof(out_file->file_url)) &&
              json_extract_string(res, "originalFilename", out_file->file_name, sizeof(out_file->file_name));
    out_file->is_image = is_image;
    free(res);
    return ok;
}

bool rakutenai_thread_upload_file(
    rakutenai_thread_t* thread,
    const uint8_t* file_data,
    size_t file_len,
    const char* filename,
    const char* mime_type,
    bool is_image,
    rakutenai_uploaded_file_t* out_file
) {
    if (!thread) return false;
    return rakutenai_user_upload_file(&thread->user, file_data, file_len, filename, mime_type, is_image, thread->id, out_file);
}

bool rakutenai_thread_create_share(
    rakutenai_thread_t* thread,
    const char** message_ids,
    size_t message_ids_count,
    char* out_share_url,
    size_t share_url_size
) {
    if (!thread || !message_ids || !out_share_url) return false;

    const char* endpoint = "/api/v1/share/create";
    char ts[32], nonce[64], sig[128];
    get_signed_headers("POST", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    wchar_t wh[2048];
    swprintf(wh, sizeof(wh)/sizeof(wh[0]),
        L"Content-Type: application/json\r\n"
        L"Authorization: Bearer %hs\r\n"
        L"X-Platform: WEB\r\n"
        L"X-Country-Code: JP\r\n"
        L"Device-ID: %hs\r\n"
        L"X-Timestamp: %hs\r\n"
        L"X-Nonce: %hs\r\n"
        L"X-Signature: %hs\r\n",
        thread->user.access_token, thread->user.device_id, ts, nonce, sig);

    char body[4096];
    size_t off = snprintf(body, sizeof(body), "{\"threadId\":\"%s\",\"messageIds\":[", thread->id);
    for (size_t i = 0; i < message_ids_count && off < sizeof(body) - 64; ++i) {
        if (i > 0) off += snprintf(body + off, sizeof(body) - off, ",");
        off += snprintf(body + off, sizeof(body) - off, "\"%s\"", message_ids[i]);
    }
    snprintf(body + off, sizeof(body) - off, "]}");

    char* res = http_request(BASE_HOST, endpoint, "POST", wh, body, strlen(body), NULL);
    if (!res) return false;

    bool ok = json_extract_string(res, "shareUrl", out_share_url, share_url_size);
    free(res);
    return ok;
}

void rakutenai_thread_close(rakutenai_thread_t* thread) {
    if (!thread) return;
    if (thread->hWebSocket) {
        WinHttpWebSocketClose(thread->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(thread->hWebSocket);
        thread->hWebSocket = NULL;
    }
    if (thread->hRequest) { WinHttpCloseHandle(thread->hRequest); thread->hRequest = NULL; }
    if (thread->hConnect) { WinHttpCloseHandle(thread->hConnect); thread->hConnect = NULL; }
    if (thread->hSession) { WinHttpCloseHandle(thread->hSession); thread->hSession = NULL; }
}

void rakutenai_thread_free(rakutenai_thread_t* thread) {
    if (!thread) return;
    rakutenai_thread_close(thread);
    free(thread);
}
