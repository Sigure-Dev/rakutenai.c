#ifndef RAKUTENAI_H
#define RAKUTENAI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define RAKUTENAI_DEFAULT_AGENT_ID "6812e64f9dfaf301f7000001"

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

/* User API */
bool rakutenai_user_create(rakutenai_user_t* out_user);
bool rakutenai_user_refresh_token(rakutenai_user_t* user);
bool rakutenai_user_upload_file(
    rakutenai_user_t* user,
    const uint8_t* file_data,
    size_t file_len,
    const char* filename,
    const char* mime_type,
    bool is_image,
    const char* thread_id_opt,
    rakutenai_uploaded_file_t* out_file
);

/* Thread API */
rakutenai_thread_t* rakutenai_thread_create(
    rakutenai_user_t* user,
    const char* title,
    const char* agent_id_opt,
    const char* shareable_link_id_opt
);

rakutenai_thread_t* rakutenai_thread_from_shared(
    rakutenai_user_t* user,
    const char* share_id
);

const char* rakutenai_thread_get_id(const rakutenai_thread_t* thread);

bool rakutenai_thread_connect(rakutenai_thread_t* thread);

bool rakutenai_thread_send_message(
    rakutenai_thread_t* thread,
    const rakutenai_content_t* contents,
    size_t contents_count,
    rakutenai_chat_mode_t mode,
    rakutenai_event_cb callback,
    void* user_data
);

bool rakutenai_thread_upload_file(
    rakutenai_thread_t* thread,
    const uint8_t* file_data,
    size_t file_len,
    const char* filename,
    const char* mime_type,
    bool is_image,
    rakutenai_uploaded_file_t* out_file
);

bool rakutenai_thread_create_share(
    rakutenai_thread_t* thread,
    const char** message_ids,
    size_t message_ids_count,
    char* out_share_url,
    size_t share_url_size
);

void rakutenai_thread_close(rakutenai_thread_t* thread);
void rakutenai_thread_free(rakutenai_thread_t* thread);

#ifdef __cplusplus
}
#endif

#endif /* RAKUTENAI_H */
