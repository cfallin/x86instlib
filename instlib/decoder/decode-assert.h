#ifndef _DECODE_ASSERT_H_
#define _DECODE_ASSERT_H_

#include <setjmp.h>

extern jmp_buf ptlsim_decoder_assert_jmpbuf;

#ifdef assert
#undef assert
#endif

#define assert(x) do { if (!(x)) longjmp(ptlsim_decoder_assert_jmpbuf, 1); } while(0)

#endif
