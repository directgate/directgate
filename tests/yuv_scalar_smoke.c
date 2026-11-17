/* The yuv_smoke checks against the scalar loops that every target without a
 * vector form of src/agent/yuv.c keeps (armhf, 32-bit x86 without SSE2). This
 * target builds yuv.c with DIRECTGATE_YUV_SCALAR, so those loops are held to
 * the same reference here on any host. */

#define YUV_SMOKE_NAME "yuv_scalar_smoke"
#include "yuv_smoke.c"
