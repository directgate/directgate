/*!
 * @file directgate-agent/src/common/version.h
 * @brief Common version definitions.
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
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __DIRECTGATE_VERSION_H__
#define __DIRECTGATE_VERSION_H__

#define DIRECTGATE_VERSION_MAJOR 1
#define DIRECTGATE_VERSION_MINOR 0
#define DIRECTGATE_VERSION_BUILD 19
#define DIRECTGATE_VERSION_PKG   5

const char* DirectGate_GetVersionShort(void);
const char* DirectGate_GetVersionLong(void);

#endif
