REM x64
REM Dependencies: NASM for openssl, Perl to run Configure
REM first, extract the tar gz files
REM build zlib, openssl, libffi static libraries
REM generate a zip out of Python's lib folder (so __pycache__ aren't in it)
REM run python's build.bat
REM copy the static libraries into Python's external folder
REM freeze our zipimport.py
REM copy the updated vc project files into Python's PCBuild folder
REM copy the cba_ files into the appropriate directories
REM msbuild Python solution- this generates all the PYDs
REM generate zip of Python's PCBuild\amd64
REM msbuild Pythoncore.dll <- done
REM 

\Python38\python scripts\untar.py zlib-1.2.11.tar.gz
\Python38\python scripts\untar.py openssl-1.1.1g.tar.gz
\Python38\python scripts\untar.py Python-3.8.2.tgz

copy zlib-patch\zlibstat.vcxproj zlib-1.2.11\contrib\vstudio\vc14

REM Build zlib static library
REM
pushd zlib-1.2.11\contrib\vstudio\vc14
msbuild zlibstat.vcxproj -p:Configuration=ReleaseWithoutAsm -t:Clean
msbuild zlibstat.vcxproj -p:Configuration=ReleaseWithoutAsm
popd

REM Build openssl static library
REM
pushd openssl-1.1.1g
set path=%path%;c:\nasm
set path=%path%;C:\Strawberry\perl\bin
perl Configure no-zlib-dynamic no-shared no-zlib VC-WIN64A --with-zlib-include=zlib-1.2.11 --with-zlib-lib=zlib-1.2.11\contrib\vstudio\vc14\x64\ZlibStatReleaseWithoutAsm\zlibstat.lib -DOPENSSL_USE_NODELETE
nmake clean
nmake
popd

REM for win32 use VC-WIN32 instead of VC-WIN64A above.

REM ffi
pushd libffi\msvc_build\amd64
msbuild Ffi_staticLib.vcxproj -p:Configuration=Release -t:Clean
msbuild Ffi_staticLib.vcxproj -p:Configuration=Release
popd

REM do this before running build.bat as it produces __pycache__
xcopy /S /Y Python-3.8.2\Lib scripts\generated\Lib
\Python38\python.exe scripts\zip_folder.py scripts\generated\Lib scripts\generated\python382_lib.zip
\Python38\python scripts\xxd.py python38_lib scripts\generated\python382_lib.zip > Python-3.8.2\Python\cba_python38_lib.c

REM call to get externs that we will update
pushd Python-3.8.2\PCbuild
call build.bat
popd

mkdir Python-3.8.2\externals\openssl-bin-1.1.1g
mkdir Python-3.8.2\externals\openssl-bin-1.1.1g\amd64
mkdir Python-3.8.2\externals\openssl-bin-1.1.1g\amd64\include
mkdir Python-3.8.2\externals\openssl-bin-1.1.1g\amd64\include\openssl
copy openssl-1.1.1g\libcrypto.lib Python-3.8.2\externals\openssl-bin-1.1.1g\amd64
copy openssl-1.1.1g\libssl.lib Python-3.8.2\externals\openssl-bin-1.1.1g\amd64
xcopy /s openssl-1.1.1g\include\openssl Python-3.8.2\externals\openssl-bin-1.1.1g\amd64\include\openssl
copy openssl-1.1.1g\ms\applink.c Python-3.8.2\externals\openssl-bin-1.1.1g\amd64\include

REM replace the libffi with static ones for ctypes
copy /Y libffi\msvc_build\amd64\x64\Release\Ffi_staticLib_amd64.lib Python-3.8.2\externals\libffi\amd64\libffi-7.lib
copy /Y libffi\msvc_build\amd64\amd64_include\*.h Python-3.8.2\externals\libffi\amd64

REM win32:
REM copy /Y libffi\msvc_build\x86\Release\Ffi_staticLib_x86.lib Python-3.8.2\externals\libffi\win32\libffi-7.lib

del cba\cmoduleloader\python\cba_zipimport_frozen.h
Python-3.8.2\PCbuild\win32\_freeze_importlib.exe cba_zipimport cba\cba_zipimport.py cba\cmoduleloader\python\cba_zipimport_frozen.h

REM copy the vcxproj changes now, except pythoncore... we do not have pyd file yet.
copy /Y cba\settings Python-3.8.2\PCbuild
xcopy /Y /S cba\cmoduleloader Python-3.8.2
REM BUILD solution again
msbuild Python-3.8.2\PCbuild\pcbuild.sln

REM generate C array for pyd files.
copy /Y Python-3.8.2\PCbuild\amd64\*.pyd scripts\generated\pyd\win64

\Python38\python.exe scripts\zip_folder.py scripts\generated\pyd\win64 scripts\generated\python382_pyd_win64.zip
\Python38\python scripts\xxd.py python38_pyd_win64 scripts\generated\python382_pyd_win64.zip > Python-3.8.2\Python\cba_python38_pyd_win64.c

msbuild Python-3.8.2\PCbuild\pythoncore.vcxproj -p:Configuration=Release