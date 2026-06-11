/*!
 * @file directgate-agent/src/common/includes.h
 * @brief Common includes for directgate.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/".
 */

#ifndef __DIRECTGATE_INCLUDES_H__
#define __DIRECTGATE_INCLUDES_H__

#include "xstd.h"
#include "xver.h"

#ifdef _WIN32
#include <sddl.h>    /* SDDL security descriptors for private files */
#include <getopt.h>  /* MinGW-w64 ships a getopt implementation */

/* Terminal geometry compatibility: mirrors struct winsize from
   <sys/ioctl.h> so shared protocol code stays platform-free. */
struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};
#endif

#include "sys/log.h"
#include "sys/sig.h"
#include "sys/xfs.h"
#include "sys/cli.h"
#include "sys/cpu.h"
#include "sys/sync.h"
#include "sys/xtime.h"
#include "sys/srch.h"

#include "net/addr.h"
#include "net/mdtp.h"
#include "net/api.h"
#include "net/ws.h"

#include "data/json.h"
#include "data/jwt.h"
#include "data/buf.h"
#include "data/str.h"

#include "crypt/crypt.h"
#include "crypt/crc32.h"
#include "crypt/base64.h"
#include "crypt/sha256.h"
#include "crypt/hmac.h"
#include "crypt/sha1.h"
#include "crypt/md5.h"
#include "crypt/aes.h"

#ifdef OPENSSL_API_COMPAT
#undef OPENSSL_API_COMPAT
#endif

#define OPENSSL_API_COMPAT XSSL_MINIMAL_API
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#endif
