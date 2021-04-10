#ifndef __CBA_PYTHON38_LIB_H__
#define __CBA_PYTHON38_LIB_H__

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

extern const unsigned char _CBA_python38_lib[];
extern unsigned int _CBA_python38_lib_size;

#ifdef MS_WINDOWS
	#ifdef _WIN64
		extern const unsigned char _CBA_python38_pyd_win64[];
		extern unsigned int _CBA_python38_pyd_win64_size;
	#else /* WIN32 */
		extern const unsigned char _CBA_python38_pyd_win32[];
		extern unsigned int _CBA_python38_pyd_win32_size;
	#endif /* WIN32, _WIN64 */

#endif /* MS_WINDOWS*/

#endif /* __CBA_PYTHON38_LIB_H__ */