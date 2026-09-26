#ifndef RAKUTENAI_THREAD_H
#define RAKUTENAI_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

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

#endif /* RAKUTENAI_THREAD_H */
