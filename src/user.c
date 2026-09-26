#include "rakutenai/user.h"
#include "rakutenai/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#else
#include <curl/curl.h>
#endif

/* 共通HTTP通信 */
char* rakutenai_internal_http_request(const char* host, const char* path, const char* verb, const wchar_t* w_headers, const void* body, size_t body_len, size_t* out_len) {
#ifdef _WIN32
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
#else
    (void)host; (void)path; (void)verb; (void)w_headers; (void)body; (void)body_len; (void)out_len;
    return NULL;
#endif
}

bool rakutenai_user_create(rakutenai_user_t* out_user) {
    if (!out_user) return false;
    memset(out_user, 0, sizeof(*out_user));
    rakutenai_generate_device_id(out_user->device_id, sizeof(out_user->device_id));

    const char* endpoint = "/api/v2/auth/anonymous";
    char ts[32], nonce[64], sig[128];
    rakutenai_get_signed_headers("GET", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

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

    char* res = rakutenai_internal_http_request(RAKUTENAI_BASE_HOST, endpoint, "GET", wh, NULL, 0, NULL);
    if (!res) return false;

    bool ok = rakutenai_json_extract_string(res, "accessToken", out_user->access_token, sizeof(out_user->access_token)) &&
              rakutenai_json_extract_string(res, "refreshToken", out_user->refresh_token, sizeof(out_user->refresh_token));

    out_user->expires_at = (int64_t)time(NULL) + 3600;
    free(res);
    return ok;
}

bool rakutenai_user_refresh_token(rakutenai_user_t* user) {
    if (!user) return false;
    const char* endpoint = "/api/v2/auth/refresh";
    char ts[32], nonce[64], sig[128];
    rakutenai_get_signed_headers("POST", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

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

    char* res = rakutenai_internal_http_request(RAKUTENAI_BASE_HOST, endpoint, "POST", wh, body, strlen(body), NULL);
    if (!res) return false;

    bool ok = rakutenai_json_extract_string(res, "accessToken", user->access_token, sizeof(user->access_token)) &&
              rakutenai_json_extract_string(res, "refreshToken", user->refresh_token, sizeof(user->refresh_token));
    user->expires_at = (int64_t)time(NULL) + 3600;
    free(res);
    return ok;
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
    rakutenai_get_signed_headers("POST", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

    char boundary_uuid[40];
    rakutenai_generate_uuid(boundary_uuid, sizeof(boundary_uuid));
    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----WebKitFormBoundary%s", boundary_uuid);

    char act_thread_id[64];
    if (thread_id_opt && thread_id_opt[0]) {
        snprintf(act_thread_id, sizeof(act_thread_id), "%s", thread_id_opt);
    } else {
        rakutenai_generate_uuid(act_thread_id, sizeof(act_thread_id));
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

    char* res = rakutenai_internal_http_request(RAKUTENAI_BASE_HOST, endpoint, "POST", wh, body, body_size, NULL);
    free(body);
    if (!res) return false;

    memset(out_file, 0, sizeof(*out_file));
    bool ok = rakutenai_json_extract_string(res, "fileId", out_file->file_id, sizeof(out_file->file_id)) &&
              rakutenai_json_extract_string(res, "fileUrl", out_file->file_url, sizeof(out_file->file_url)) &&
              rakutenai_json_extract_string(res, "originalFilename", out_file->file_name, sizeof(out_file->file_name));
    out_file->is_image = is_image;
    free(res);
    return ok;
}
