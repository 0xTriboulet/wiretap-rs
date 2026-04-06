#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Runs wiretap CLI command parsing/execution using argv semantics.
 * Return codes:
 *   0 => success
 *   1 => command failed (see wiretap_last_error_message)
 *   2 => invalid FFI arguments
 *   3 => internal panic while executing command
 */
int32_t wiretap_run_argv(int argc, const char* const* argv);

/*
 * Returns an owned C string containing the last error message, or NULL when
 * there is no error. The returned pointer must be freed with wiretap_string_free.
 */
char* wiretap_last_error_message(void);

/* Frees memory returned by wiretap_last_error_message. */
void wiretap_string_free(char* ptr);

uint32_t wiretap_version_major(void);
uint32_t wiretap_version_minor(void);
uint32_t wiretap_version_patch(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
