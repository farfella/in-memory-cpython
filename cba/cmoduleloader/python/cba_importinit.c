/* Module definition and import implementation */

#include "Python.h"
#include "pycore_pylifecycle.h"

#include "cba_python38_lib.h"


/*
 * Called by init_importlib_external; initialized immediately before _PyImportZip_Init.
 */
PyStatus _PyCBAImport_Init(PyInterpreterState* interp)
{

    PyObject* cba_zipimport;
    int err = 0;

    int verbose = interp->config.verbose;
    if (verbose) {
        PySys_WriteStderr("# installing cba_zipimport hook\n");
    }

    cba_zipimport = PyImport_ImportModule("cba_zipimport");
    if (cba_zipimport == NULL) {
        PyErr_Clear(); /* No zip import module -- okay */
        if (verbose) {
            PySys_WriteStderr("# can't import cba_zipimport\n");
        }
    }
    else {
        _Py_IDENTIFIER(install_cba_metafinder);
        PyObject* install_cba_metafinder = _PyObject_GetAttrId(cba_zipimport,
            &PyId_install_cba_metafinder);
        Py_DECREF(cba_zipimport);
        if (install_cba_metafinder == NULL) {
            PyErr_Clear(); /* No zipimporter object -- okay */
            if (verbose) {
                PySys_WriteStderr("# can't import cba_zipimport.install_cba_metafinder\n");
            }
        }
        else {

#if defined _M_ARM
#error Building for ARM is not set up.
#endif
            PyObject* ppyd_zip_name = PyUnicode_FromString("#cba_python38_pyd.zip");
            PyObject* ppyd_zip_data =
#ifdef _WIN64            
            PyByteArray_FromStringAndSize((char*)_CBA_python38_pyd_win64, _CBA_python38_pyd_win64_size);
#else
            PyByteArray_FromStringAndSize((char*)_CBA_python38_pyd_win32, _CBA_python38_pyd_win32_size);
#endif
            PyObject* tmp_pyd = PyObject_CallFunction(install_cba_metafinder, "(OO)", ppyd_zip_name, ppyd_zip_data);
            Py_DECREF(ppyd_zip_name);
            Py_DECREF(ppyd_zip_data);
            Py_DECREF(tmp_pyd);


            PyObject* plib_zip_name = PyUnicode_FromString("#cba_python38_lib.zip");
            PyObject* plib_zip_data = PyByteArray_FromStringAndSize((char*)_CBA_python38_lib, _CBA_python38_lib_size);
            PyObject* tmp = PyObject_CallFunction(install_cba_metafinder, "(OO)", plib_zip_name, plib_zip_data);
            Py_DECREF(plib_zip_name);
            Py_DECREF(plib_zip_data);
            Py_DECREF(tmp);


            Py_DECREF(install_cba_metafinder);

            if (err < 0) {
                goto error;
            }
            if (verbose) {
                PySys_WriteStderr("# installed cba_zipimport hook\n");
            }

        }
    }

    return _PyStatus_OK();

error:
    PyErr_Print();
    return _PyStatus_ERR("initializing zipimport failed");
}
