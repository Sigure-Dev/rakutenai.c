#ifndef RAKUTENAI_USER_H
#define RAKUTENAI_USER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

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

#ifdef __cplusplus
}
#endif

#endif /* RAKUTENAI_USER_H */
