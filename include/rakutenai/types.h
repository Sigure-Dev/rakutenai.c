#ifndef RAKUTENAI_TYPES_H
#define RAKUTENAI_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define RAKUTENAI_DEFAULT_AGENT_ID "6812e64f9dfaf301f7000001"
#define RAKUTENAI_BASE_HOST "ai.rakuten.co.jp"
#define RAKUTENAI_WS_HOST "companion.ai.rakuten.co.jp"
#define RAKUTENAI_SECRET_KEY "4f0465bfea7761a510dda451ff86a935bf0c8ed6fb37f80441509c64328788c8"

typedef enum {
    RAKUTENAI_MODE_USER_INPUT = 0,
    RAKUTENAI_MODE_DEEP_THINK,
    RAKUTENAI_MODE_AI_READ
} rakutenai_chat_mode_t;

typedef enum {
    RAKUTENAI_EVENT_ACK = 0,
    RAKUTENAI_EVENT_REASONING_START,
    RAKUTENAI_EVENT_REASONING_DELTA,
    RAKUTENAI_EVENT_TEXT_DELTA,
    RAKUTENAI_EVENT_IMAGE_THUMBNAIL,
    RAKUTENAI_EVENT_IMAGE,
    RAKUTENAI_EVENT_TOOL_CALL_DETAIL,
    RAKUTENAI_EVENT_TOOL_CALL,
    RAKUTENAI_EVENT_NOTIFICATION,
    RAKUTENAI_EVENT_USAGE,
    RAKUTENAI_EVENT_DONE,
    RAKUTENAI_EVENT_ERROR,
    RAKUTENAI_EVENT_DISCONNECTED
} rakutenai_event_type_t;

typedef struct {
    rakutenai_event_type_t type;
    const char* text;
    const char* url;
    uint64_t input_tokens;
    uint64_t output_tokens;
    const char* error_message;
} rakutenai_event_t;

typedef void (*rakutenai_event_cb)(const rakutenai_event_t* event, void* user_data);

typedef struct {
    char device_id[64];
    char access_token[1024];
    char refresh_token[1024];
    int64_t expires_at;
} rakutenai_user_t;

typedef struct {
    char file_id[64];
    char file_url[512];
    char file_name[256];
    bool is_image;
} rakutenai_uploaded_file_t;

typedef enum {
    RAKUTENAI_CONTENT_TEXT = 0,
    RAKUTENAI_CONTENT_FILE
} rakutenai_content_type_t;

typedef struct {
    rakutenai_content_type_t type;
    const char* text;
    rakutenai_uploaded_file_t file;
} rakutenai_content_t;

typedef struct rakutenai_thread rakutenai_thread_t;

#ifdef __cplusplus
}
#endif

#endif /* RAKUTENAI_TYPES_H */
