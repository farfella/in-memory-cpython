REM x64
REM zlib
pushd zlib-1.2.11\contrib\vstudio\vc14
msbuild zlibstat.vcxproj -p:Configuration=ReleaseWithoutAsm -t:Clean
msbuild zlibstat.vcxproj -p:Configuration=ReleaseWithoutAsm
popd

REM openssl
pushd openssl-1.1.1g
set path=%path%;c:\nasm
set path=%path%;C:\Strawberry\perl\bin
perl Configure no-zlib-dynamic no-shared no-zlib VC-WIN64A --with-zlib-include=zlib-1.2.11 --with-zlib-lib=zlib-1.2.11\contrib\vstudio\vc14\x64\ZlibStatReleaseWithoutAsm\zlibstat.lib -DOPENSSL_USE_NODELETE
nmake clean
nmake
popd

% for win32 use VC-WIN32 instead of VC-WIN64A above.

REM ffi
pushd libffi\msvc_build\amd64
msbuild Ffi_staticLib.vcxproj -p:Configuration=Release -t:Clean
msbuild Ffi_staticLib.vcxproj -p:Configuration=Release
popd

pushd Python-3.8.2\PCbuild
build.bat
popd

mkdir Python-3.8.2\openssl-bin-1.1.1g\amd64
copy openssl-1.1.1g\libcrypto.lib Python-3.8.2\externals\openssl-bin-1.1.1g\amd64
copy openssl-1.1.1g\libssl.lib Python-3.8.2\externals\openssl-bin-1.1.1g\amd64
copy openssl-1.1.1g\include\openssl Python-3.8.2\externals\openssl-bin-1.1.1g\amd64\include\openssl
copy openssl-1.1.1g\ms\applink.c Python-3.8.2\externals\openssl-bin-1.1.1g\amd64\include

copy /Y libffi\msvc_build\amd64\x64\Release\Ffi_staticLib_amd64.lib Python-3.8.2\externals\libffi\amd64\libffi-7.lib

copy /Y libffi\msvc_build\x86\Release\Ffi_staticLib_x86.lib Python-3.8.2\externals\libffi\win32\libffi-7.lib

copy /Y libffi\msvc_build\amd64\amd64_include\*.h Python-3.8.2\externals\libffi\amd64


Python-3.8.2\PCbuild\win32\_freeze_importlib.exe cba_zipimport cba\cba_zipimport.py cba\cba_zipimport_frozen.h

\python38\python xxd\xxd.py python38_lib C:\Work\papers\usenix\2021\code\Python-3.8.2\Lib\python382_lib.zip > C:\Work\papers\usenix\2021\code\Python-3.8.2\Python\cba_python38_lib.c

\python38\python xxd\xxd.py python38_pyd_win32 C:\Work\papers\usenix\2021\code\Python-3.8.2\PCbuild\win32\python382_pyd_win32.zip > C:\Work\papers\usenix\2021\code\Python-3.8.2\Python\cba_python38_pyd_win32.c

\python38\python xxd\xxd.py python38_pyd_win64 C:\Work\papers\usenix\2021\code\Python-3.8.2\PCbuild\amd64\python382_pyd_win64.zip > C:\Work\papers\usenix\2021\code\Python-3.8.2\Python\cba_python38_pyd_win64.c