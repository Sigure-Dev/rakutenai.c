#include "rakutenai/thread.h"
#include "rakutenai/crypto.h"
#include "rakutenai/user.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#endif

extern char* rakutenai_internal_http_request(const char* host, const char* path, const char* verb, const wchar_t* w_headers, const void* body, size_t body_len, size_t* out_len);

struct rakutenai_thread {
    char id[64];
    rakutenai_user_t user;
#ifdef _WIN32
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    HINTERNET hWebSocket;
#endif
};

rakutenai_thread_t* rakutenai_thread_create(
    rakutenai_user_t* user,
    const char* title,
    const char* agent_id_opt,
    const char* shareable_link_id_opt
) {
    if (!user) return NULL;

    const char* endpoint = "/api/v1/thread";
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

    const char* aid = agent_id_opt ? agent_id_opt : RAKUTENAI_DEFAULT_AGENT_ID;
    const char* t = title ? title : "新しいスレッド";

    char body[1024];
    if (shareable_link_id_opt) {
        snprintf(body, sizeof(body), "{\"scenarioAgentId\":\"%s\",\"title\":\"%s\",\"shareableLinkId\":\"%s\",\"multipleThreadMode\":true}", aid, t, shareable_link_id_opt);
    } else {
        snprintf(body, sizeof(body), "{\"scenarioAgentId\":\"%s\",\"title\":\"%s\"}", aid, t);
    }

    char* res = rakutenai_internal_http_request(RAKUTENAI_BASE_HOST, endpoint, "POST", wh, body, strlen(body), NULL);
    if (!res) return NULL;

    rakutenai_thread_t* thread = (rakutenai_thread_t*)calloc(1, sizeof(rakutenai_thread_t));
    if (!thread) { free(res); return NULL; }

    thread->user = *user;
    if (!rakutenai_json_extract_string(res, "id", thread->id, sizeof(thread->id))) {
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
    rakutenai_get_signed_headers("GET", endpoint, NULL, ts, sizeof(ts), nonce, sizeof(nonce), sig, sizeof(sig));

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

    char* res = rakutenai_internal_http_request(RAKUTENAI_BASE_HOST, endpoint, "GET", wh, NULL, 0, NULL);
    if (!res) return NULL;

    char title[256] = "Shared Thread";
    char agent_id[64] = RAKUTENAI_DEFAULT_AGENT_ID;
    rakutenai_json_extract_string(res, "title", title, sizeof(title));
    rakutenai_json_extract_string(res, "scenarioAgentId", agent_id, sizeof(agent_id));
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

#ifdef _WIN32
    time_t now = time(NULL);
    char ts[32], nonce[64], sig[128];
    snprintf(ts, sizeof(ts), "%lld", (long long)now);
    rakutenai_generate_uuid(nonce, sizeof(nonce));

    char sorted[2048];
    snprintf(sorted, sizeof(sorted), "accessToken=%sdeviceId=%splatform=WEB", thread->user.access_token, thread->user.device_id);

    char raw[4096];
    snprintf(raw, sizeof(raw), "GET/ws/v1/chat%s%s%s", sorted, ts, nonce);
    rakutenai_hmac_sha256(raw, RAKUTENAI_SECRET_KEY, sig, sizeof(sig));

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
#else
    return true;
#endif
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
#ifdef _WIN32
    if (!thread || !thread->hWebSocket) return false;

    char user_msg_id[40];
    rakutenai_generate_uuid(user_msg_id, sizeof(user_msg_id));
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
                    if (rakutenai_json_extract_string(msg, "thumbnail", thumb, sizeof(thumb))) {
                        rakutenai_event_t ev = { RAKUTENAI_EVENT_IMAGE_THUMBNAIL, NULL, thumb, 0, 0, NULL };
                        if (callback) callback(&ev, user_data);
                    }
                    if (rakutenai_json_extract_string(msg, "preview", prev, sizeof(prev))) {
                        rakutenai_event_t ev = { RAKUTENAI_EVENT_IMAGE, NULL, prev, 0, 0, NULL };
                        if (callback) callback(&ev, user_data);
                    }
                }

                if (strstr(msg, "\"responseMetricsData\"")) {
                    uint64_t in_tok = 0, out_tok = 0;
                    rakutenai_json_extract_uint64(msg, "inputTokens", &in_tok);
                    rakutenai_json_extract_uint64(msg, "outputTokens", &out_tok);
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
#else
    (void)thread; (void)contents; (void)contents_count; (void)mode; (void)callback; (void)user_data;
    return false;
#endif
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
        thread->user.access_token, thread->user.device_id, ts, nonce, sig);

    char body[4096];
    size_t off = snprintf(body, sizeof(body), "{\"threadId\":\"%s\",\"messageIds\":[", thread->id);
    for (size_t i = 0; i < message_ids_count && off < sizeof(body) - 64; ++i) {
        if (i > 0) off += snprintf(body + off, sizeof(body) - off, ",");
        off += snprintf(body + off, sizeof(body) - off, "\"%s\"", message_ids[i]);
    }
    snprintf(body + off, sizeof(body) - off, "]}");

    char* res = rakutenai_internal_http_request(RAKUTENAI_BASE_HOST, endpoint, "POST", wh, body, strlen(body), NULL);
    if (!res) return false;

    bool ok = rakutenai_json_extract_string(res, "shareUrl", out_share_url, share_url_size);
    free(res);
    return ok;
}

void rakutenai_thread_close(rakutenai_thread_t* thread) {
    if (!thread) return;
#ifdef _WIN32
    if (thread->hWebSocket) {
        WinHttpWebSocketClose(thread->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(thread->hWebSocket);
        thread->hWebSocket = NULL;
    }
    if (thread->hRequest) { WinHttpCloseHandle(thread->hRequest); thread->hRequest = NULL; }
    if (thread->hConnect) { WinHttpCloseHandle(thread->hConnect); thread->hConnect = NULL; }
    if (thread->hSession) { WinHttpCloseHandle(thread->hSession); thread->hSession = NULL; }
#endif
}

void rakutenai_thread_free(rakutenai_thread_t* thread) {
    if (!thread) return;
    rakutenai_thread_close(thread);
    free(thread);
}
