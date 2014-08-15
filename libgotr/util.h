#ifndef _GOTR_UTIL_H
#define _GOTR_UTIL_H

#include <gcrypt.h>

#define GOTR_OK 1
#define SERIALIZED_POINT_LEN (256/8)

struct gotr_point {
	unsigned char data[SERIALIZED_POINT_LEN];
};

void gotr_eprintf(const char *format, ...);

# undef gotr_assert
# undef gotr_assert_perror
# undef gotr_assert_gpgerr

#ifdef NDEBUG

# define gotr_assert(expr)          ((void)(0))
# define gotr_assert_perror(errnum) ((void)(0))
# define gotr_assert_gpgerr(errnum) ((void)(0))

#else /* NDEBUG */

void gotr_assert_fail(const char *assertion, const char *file, unsigned int line, const char *function);
void gotr_assert_perror_fail(int errnum, const char *file, unsigned int line, const char *function);
void gotr_assert_gpgerr_fail(gcry_error_t errnum, const char *file, unsigned int line, const char *function);

# define gotr_assert(expr)          ((expr)    ? (void)(0) : gotr_assert_fail ((#expr), __FILE__, __LINE__, __PRETTY_FUNCTION__))
# define gotr_assert_perror(errnum) (!(errnum) ? (void)(0) : gotr_assert_perror_fail ((errnum), __FILE__, __LINE__, __PRETTY_FUNCTION__))
# define gotr_assert_gpgerr(errnum) (!(errnum) ? (void)(0) : gotr_assert_gpgerr_fail ((errnum), __FILE__, __LINE__, __PRETTY_FUNCTION__))

#endif /* NDEBUG */

#endif
