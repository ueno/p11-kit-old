/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2012 Red Hat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "library.h"
#include "virtual.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_FFI

/*
 * We use libffi to build closures. Note that even with libffi certain
 * platforms do not support using ffi_closure. In this case FFI_CLOSURES will
 * not be defined. This is checked in configure.ac
 */

/*
 * Since libffi uses shared memory to store that, releasing it
 * will cause issues on any other child or parent process that relies
 * on that. Don't release it.
 */
#define LIBFFI_FREE_CLOSURES 0

#include "ffi.h"
#ifndef FFI_CLOSURES
#error "FFI_CLOSURES should be checked in configure.ac"
#endif

/* There are 66 functions in PKCS#11, with a maximum of 8 args */
#define MAX_FUNCTIONS 66
#define MAX_ARGS 10

typedef struct {
	/* This is first so we can cast between CK_FUNCTION_LIST* and Context* */
	CK_FUNCTION_LIST bound;

	/* The PKCS#11 functions to call into */
	p11_virtual *virt;
	p11_destroyer destroyer;

	/* A list of our libffi built closures, for cleanup later */
	ffi_closure *ffi_closures[MAX_FUNCTIONS];
	ffi_cif ffi_cifs[MAX_FUNCTIONS];
	int ffi_used;
} Wrapper;

static CK_RV
short_C_GetFunctionStatus (CK_SESSION_HANDLE handle)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV
short_C_CancelFunction (CK_SESSION_HANDLE handle)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

static void
binding_C_GetFunctionList (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           Wrapper *wrapper)
{
	CK_FUNCTION_LIST_PTR_PTR list = *(CK_FUNCTION_LIST_PTR_PTR *)args[0];

	if (list == NULL) {
		*ret = CKR_ARGUMENTS_BAD;
	} else {
		*list = &wrapper->bound;
		*ret = CKR_OK;
	}
}

static void
binding_C_Initialize (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Initialize (funcs,
	                            *(CK_VOID_PTR *)args[0]);
}

static void
binding_C_Finalize (ffi_cif *cif,
                    CK_RV *ret,
                    void* args[],
                    CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Finalize (funcs,
	                          *(CK_VOID_PTR *)args[0]);
}

static void
binding_C_GetInfo (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetInfo (funcs,
	                         *(CK_INFO_PTR *)args[0]);
}

static void
binding_C_GetSlotList (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetSlotList (funcs,
	                             *(CK_BBOOL *)args[0],
	                             *(CK_SLOT_ID_PTR *)args[1],
	                             *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_GetSlotInfo (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetSlotInfo (funcs,
	                             *(CK_SLOT_ID *)args[0],
	                             *(CK_SLOT_INFO_PTR *)args[1]);
}

static void
binding_C_GetTokenInfo (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetTokenInfo (funcs,
	                              *(CK_SLOT_ID *)args[0],
	                              *(CK_TOKEN_INFO_PTR *)args[1]);
}

static void
binding_C_WaitForSlotEvent (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_WaitForSlotEvent (funcs,
	                                  *(CK_FLAGS *)args[0],
	                                  *(CK_SLOT_ID_PTR *)args[1],
	                                  *(CK_VOID_PTR *)args[2]);
}

static void
binding_C_GetMechanismList (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetMechanismList (funcs,
	                                  *(CK_SLOT_ID *)args[0],
	                                  *(CK_MECHANISM_TYPE_PTR *)args[1],
	                                  *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_GetMechanismInfo (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetMechanismInfo (funcs,
	                                  *(CK_SLOT_ID *)args[0],
	                                  *(CK_MECHANISM_TYPE *)args[1],
	                                  *(CK_MECHANISM_INFO_PTR *)args[2]);
}

static void
binding_C_InitToken (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_InitToken (funcs,
	                           *(CK_SLOT_ID *)args[0],
	                           *(CK_BYTE_PTR *)args[1],
	                           *(CK_ULONG *)args[2],
	                           *(CK_BYTE_PTR *)args[3]);
}

static void
binding_C_InitPIN (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_InitPIN (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_BYTE_PTR *)args[1],
	                         *(CK_ULONG *)args[2]);
}

static void
binding_C_SetPIN (ffi_cif *cif,
                  CK_RV *ret,
                  void* args[],
                  CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SetPIN (funcs,
	                        *(CK_SESSION_HANDLE *)args[0],
	                        *(CK_BYTE_PTR *)args[1],
	                        *(CK_ULONG *)args[2],
	                        *(CK_BYTE_PTR *)args[3],
	                        *(CK_ULONG *)args[4]);
}

static void
binding_C_OpenSession (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_OpenSession (funcs,
	                             *(CK_SLOT_ID *)args[0],
	                             *(CK_FLAGS *)args[1],
	                             *(CK_VOID_PTR *)args[2],
	                             *(CK_NOTIFY *)args[3],
	                             *(CK_SESSION_HANDLE_PTR *)args[4]);
}

static void
binding_C_CloseSession (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CloseSession (funcs,
	                              *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_CloseAllSessions (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CloseAllSessions (funcs,
	                                  *(CK_SLOT_ID *)args[0]);
}

static void
binding_C_GetSessionInfo (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetSessionInfo (funcs,
	                                *(CK_SESSION_HANDLE *)args[0],
	                                *(CK_SESSION_INFO_PTR *)args[1]);
}

static void
binding_C_GetOperationState (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetOperationState (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_BYTE_PTR *)args[1],
	                                   *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_SetOperationState (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SetOperationState (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_BYTE_PTR *)args[1],
	                                   *(CK_ULONG *)args[2],
	                                   *(CK_OBJECT_HANDLE *)args[3],
	                                   *(CK_OBJECT_HANDLE *)args[4]);
}

static void
binding_C_Login (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Login (funcs,
	                       *(CK_SESSION_HANDLE *)args[0],
	                       *(CK_USER_TYPE *)args[1],
	                       *(CK_BYTE_PTR *)args[2],
	                       *(CK_ULONG *)args[3]);
}

static void
binding_C_Logout (ffi_cif *cif,
                  CK_RV *ret,
                  void* args[],
                  CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Logout (funcs,
	                        *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_CreateObject (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CreateObject (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_ATTRIBUTE_PTR *)args[1],
	                              *(CK_ULONG *)args[2],
	                              *(CK_OBJECT_HANDLE_PTR *)args[3]);
}

static void
binding_C_CopyObject (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CopyObject (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_OBJECT_HANDLE *)args[1],
	                            *(CK_ATTRIBUTE_PTR *)args[2],
	                            *(CK_ULONG *)args[3],
	                            *(CK_OBJECT_HANDLE_PTR *)args[4]);
}

static void
binding_C_DestroyObject (ffi_cif *cif,
                         CK_RV *ret,
                         void* args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DestroyObject (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_OBJECT_HANDLE *)args[1]);
}

static void
binding_C_GetObjectSize (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetObjectSize (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_OBJECT_HANDLE *)args[1],
	                               *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_GetAttributeValue (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetAttributeValue (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_OBJECT_HANDLE *)args[1],
	                                   *(CK_ATTRIBUTE_PTR *)args[2],
	                                   *(CK_ULONG *)args[3]);
}

static void
binding_C_SetAttributeValue (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SetAttributeValue (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_OBJECT_HANDLE *)args[1],
	                                   *(CK_ATTRIBUTE_PTR *)args[2],
	                                   *(CK_ULONG *)args[3]);
}

static void
binding_C_FindObjectsInit (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_FindObjectsInit (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_ATTRIBUTE_PTR *)args[1],
	                                 *(CK_ULONG *)args[2]);
}

static void
binding_C_FindObjects (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_FindObjects (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_OBJECT_HANDLE_PTR *)args[1],
	                             *(CK_ULONG *)args[2],
	                             *(CK_ULONG_PTR *)args[3]);
}

static void
binding_C_FindObjectsFinal (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_FindObjectsFinal (funcs,
	                                  *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_EncryptInit (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptInit (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_MECHANISM_PTR *)args[1],
	                             *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Encrypt (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Encrypt (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_BYTE_PTR *)args[1],
	                         *(CK_ULONG *)args[2],
	                         *(CK_BYTE_PTR *)args[3],
	                         *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_EncryptUpdate (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptUpdate (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_BYTE_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_EncryptFinal (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptFinal (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_DecryptInit (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptInit (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_MECHANISM_PTR *)args[1],
	                             *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Decrypt (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Decrypt (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_BYTE_PTR *)args[1],
	                         *(CK_ULONG *)args[2],
	                         *(CK_BYTE_PTR *)args[3],
	                         *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptUpdate (ffi_cif *cif,
                         CK_RV *ret,
                         void* args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptUpdate (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_BYTE_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptFinal (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptFinal (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_DigestInit (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestInit (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_MECHANISM_PTR *)args[1]);
}

static void
binding_C_Digest (ffi_cif *cif,
                  CK_RV *ret,
                  void* args[],
                  CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Digest (funcs,
	                        *(CK_SESSION_HANDLE *)args[0],
	                        *(CK_BYTE_PTR *)args[1],
	                        *(CK_ULONG *)args[2],
	                        *(CK_BYTE_PTR *)args[3],
	                        *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DigestUpdate (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestUpdate (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG *)args[2]);
}

static void
binding_C_DigestKey (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestKey (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_OBJECT_HANDLE *)args[1]);
}

static void
binding_C_DigestFinal (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestFinal (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_BYTE_PTR *)args[1],
	                             *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_SignInit (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignInit (funcs,
	                          *(CK_SESSION_HANDLE *)args[0],
	                          *(CK_MECHANISM_PTR *)args[1],
	                          *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Sign (ffi_cif *cif,
                CK_RV *ret,
                void* args[],
                CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Sign (funcs,
	                      *(CK_SESSION_HANDLE *)args[0],
	                      *(CK_BYTE_PTR *)args[1],
	                      *(CK_ULONG *)args[2],
	                      *(CK_BYTE_PTR *)args[3],
	                      *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_SignUpdate (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignUpdate (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_BYTE_PTR *)args[1],
	                            *(CK_ULONG *)args[2]);
}

static void
binding_C_SignFinal (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignFinal (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_BYTE_PTR *)args[1],
	                           *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_SignRecoverInit (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignRecoverInit (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_MECHANISM_PTR *)args[1],
	                                 *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_SignRecover (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignRecover (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_BYTE_PTR *)args[1],
	                             *(CK_ULONG *)args[2],
	                             *(CK_BYTE_PTR *)args[3],
	                             *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_VerifyInit (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyInit (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_MECHANISM_PTR *)args[1],
	                            *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Verify (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Verify (funcs,
	                        *(CK_SESSION_HANDLE *)args[0],
	                        *(CK_BYTE_PTR *)args[1],
	                        *(CK_ULONG *)args[2],
	                        *(CK_BYTE_PTR *)args[3],
	                        *(CK_ULONG *)args[4]);
}

static void
binding_C_VerifyUpdate (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyUpdate (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG *)args[2]);
}

static void
binding_C_VerifyFinal (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyFinal (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_BYTE_PTR *)args[1],
	                             *(CK_ULONG *)args[2]);
}

static void
binding_C_VerifyRecoverInit (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyRecoverInit (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_MECHANISM_PTR *)args[1],
	                                   *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_VerifyRecover (ffi_cif *cif,
                         CK_RV *ret,
                         void* args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyRecover (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_BYTE_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DigestEncryptUpdate (ffi_cif *cif,
                               CK_RV *ret,
                               void* args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestEncryptUpdate (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_BYTE_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptDigestUpdate (ffi_cif *cif,
                               CK_RV *ret,
                               void* args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptDigestUpdate (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_BYTE_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_SignEncryptUpdate (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignEncryptUpdate (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_BYTE_PTR *)args[1],
	                                   *(CK_ULONG *)args[2],
	                                   *(CK_BYTE_PTR *)args[3],
	                                   *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptVerifyUpdate (ffi_cif *cif,
                               CK_RV *ret,
                               void* args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptVerifyUpdate (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_BYTE_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_GenerateKey (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GenerateKey (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_MECHANISM_PTR *)args[1],
	                             *(CK_ATTRIBUTE_PTR *)args[2],
	                             *(CK_ULONG *)args[3],
	                             *(CK_OBJECT_HANDLE_PTR *)args[4]);
}

static void
binding_C_GenerateKeyPair (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GenerateKeyPair (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_MECHANISM_PTR *)args[1],
	                                 *(CK_ATTRIBUTE_PTR *)args[2],
	                                 *(CK_ULONG *)args[3],
	                                 *(CK_ATTRIBUTE_PTR *)args[4],
	                                 *(CK_ULONG *)args[5],
	                                 *(CK_OBJECT_HANDLE_PTR *)args[6],
	                                 *(CK_OBJECT_HANDLE_PTR *)args[7]);
}

static void
binding_C_WrapKey (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_WrapKey (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_MECHANISM_PTR *)args[1],
	                         *(CK_OBJECT_HANDLE *)args[2],
	                         *(CK_OBJECT_HANDLE *)args[3],
	                         *(CK_BYTE_PTR *)args[4],
	                         *(CK_ULONG_PTR *)args[5]);
}

static void
binding_C_UnwrapKey (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_UnwrapKey (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_MECHANISM_PTR *)args[1],
	                           *(CK_OBJECT_HANDLE *)args[2],
	                           *(CK_BYTE_PTR *)args[3],
	                           *(CK_ULONG *)args[4],
	                           *(CK_ATTRIBUTE_PTR *)args[5],
	                           *(CK_ULONG *)args[6],
	                           *(CK_OBJECT_HANDLE_PTR *)args[7]);
}

static void
binding_C_DeriveKey (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DeriveKey (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_MECHANISM_PTR *)args[1],
	                           *(CK_OBJECT_HANDLE *)args[2],
	                           *(CK_ATTRIBUTE_PTR *)args[3],
	                           *(CK_ULONG *)args[4],
	                           *(CK_OBJECT_HANDLE_PTR *)args[5]);
}

static void
binding_C_SeedRandom (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SeedRandom (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_BYTE_PTR *)args[1],
	                            *(CK_ULONG *)args[2]);
}

static void
binding_C_GenerateRandom (ffi_cif *cif,
                          CK_RV *ret,
                          void* args[],
                          CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GenerateRandom (funcs,
	                                *(CK_SESSION_HANDLE *)args[0],
	                                *(CK_BYTE_PTR *)args[1],
	                                *(CK_ULONG *)args[2]);
}

#endif /* WITH_FFI */

#include "p11-kit/virtual-stack.c"
#include "p11-kit/virtual-base.c"

void
p11_virtual_init (p11_virtual *virt,
                  CK_X_FUNCTION_LIST *funcs,
                  void *lower_module,
                  p11_destroyer lower_destroy)
{
	memcpy (virt, funcs, sizeof (CK_X_FUNCTION_LIST));
	virt->lower_module = lower_module;
	virt->lower_destroy = lower_destroy;
}

void
p11_virtual_uninit (p11_virtual *virt)
{
	if (virt->lower_destroy)
		(virt->lower_destroy) (virt->lower_module);
}

#ifdef WITH_FFI

typedef struct {
	const char *name;
	void *binding_function;
	void *stack_fallback;
	size_t virtual_offset;
	void *base_fallback;
	size_t module_offset;
	ffi_type *types[MAX_ARGS];
} FunctionInfo;

#define STRUCT_OFFSET(struct_type, member) \
	((size_t) ((unsigned char *) &((struct_type *) 0)->member))
#define STRUCT_MEMBER_P(struct_p, struct_offset) \
	((void *) ((unsigned char *) (struct_p) + (long) (struct_offset)))
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
	(*(member_type*) STRUCT_MEMBER_P ((struct_p), (struct_offset)))

#define FUNCTION(name) \
	#name, binding_C_##name, \
	stack_C_##name, STRUCT_OFFSET (CK_X_FUNCTION_LIST, C_##name), \
	base_C_##name, STRUCT_OFFSET (CK_FUNCTION_LIST, C_##name)

static const FunctionInfo function_info[] = {
	{ FUNCTION (Initialize), { &ffi_type_pointer, NULL } },
	{ FUNCTION (Finalize), { &ffi_type_pointer, NULL } },
	{ FUNCTION (GetInfo), { &ffi_type_pointer, NULL } },
	{ FUNCTION (GetSlotList), { &ffi_type_uchar, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetSlotInfo), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetTokenInfo), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (WaitForSlotEvent), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetMechanismList), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetMechanismInfo), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (InitToken), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (InitPIN), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SetPIN), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (OpenSession), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (CloseSession), { &ffi_type_ulong, NULL } },
	{ FUNCTION (CloseAllSessions), { &ffi_type_ulong, NULL } },
	{ FUNCTION (GetSessionInfo), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetOperationState), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SetOperationState), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_ulong, &ffi_type_ulong, NULL } },
	{ FUNCTION (Login), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Logout), { &ffi_type_ulong, NULL } },
	{ FUNCTION (CreateObject), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (CopyObject), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (DestroyObject), { &ffi_type_ulong, &ffi_type_ulong, NULL } },
	{ FUNCTION (GetObjectSize), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetAttributeValue), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SetAttributeValue), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (FindObjectsInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (FindObjects), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (FindObjectsFinal), { &ffi_type_ulong, NULL } },
	{ FUNCTION (EncryptInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Encrypt), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (EncryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (EncryptFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Decrypt), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DigestInit), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (Digest), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DigestUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (DigestKey), { &ffi_type_ulong, &ffi_type_ulong, NULL } },
	{ FUNCTION (DigestFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Sign), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SignFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignRecoverInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SignRecover), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (VerifyInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Verify), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyRecoverInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyRecover), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DigestEncryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptDigestUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignEncryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptVerifyUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GenerateKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GenerateKeyPair), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (WrapKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (UnwrapKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (DeriveKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (SeedRandom), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (GenerateRandom), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ 0, }
};

static bool
lookup_fall_through (p11_virtual *virt,
                     const FunctionInfo *info,
                     void **bound_func)
{
	void *func;

	/*
	 * So the basic concept here is if we have only fall-through functions
	 * all the way down the stack, then we can just get the actual module
	 * function, so that calls go right through.
	 */

	func = STRUCT_MEMBER (void *, virt, info->virtual_offset);

	/*
	 * This is a fall-through function and the stack goes down further, so
	 * ask the next level down for the
	 */
	if (func == info->stack_fallback) {
		return lookup_fall_through (virt->lower_module, info, bound_func);

	/*
	 * This is a fall-through function at the bottom level of the stack
	 * so return the function from the module.
	 */
	} else if (func == info->base_fallback) {
		*bound_func = STRUCT_MEMBER (void *, virt->lower_module, info->module_offset);
		return true;
	}

	return false;
}

static bool
bind_ffi_closure (Wrapper *wrapper,
                  void *binding_data,
                  void *binding_func,
                  ffi_type **args,
                  void **bound_func)
{
	ffi_closure *clo;
	ffi_cif *cif;
	int nargs = 0;
	int i = 0;
	int ret;

	assert (wrapper->ffi_used < MAX_FUNCTIONS);
	cif = wrapper->ffi_cifs + wrapper->ffi_used;

	/* The number of arguments */
	for (i = 0, nargs = 0; args[i] != NULL; i++)
		nargs++;

	assert (nargs <= MAX_ARGS);

	/*
	 * The failures here are unexpected conditions. There's a chance they
	 * might occur on other esoteric platforms, so we take a little
	 * extra care to print relevant debugging info, and return a status,
	 * so that we can get back useful debug info on platforms that we
	 * don't have access to.
	 */

	ret = ffi_prep_cif (cif, FFI_DEFAULT_ABI, nargs, &ffi_type_ulong, args);
	if (ret != FFI_OK) {
		p11_debug_precond ("ffi_prep_cif failed: %d\n", ret);
		return false;
	}

	clo = ffi_closure_alloc (sizeof (ffi_closure), bound_func);
	if (clo == NULL) {
		p11_debug_precond ("ffi_closure_alloc failed\n");
		return false;
	}

	ret = ffi_prep_closure_loc (clo, cif, binding_func, binding_data, *bound_func);
	if (ret != FFI_OK) {
		p11_debug_precond ("ffi_prep_closure_loc failed: %d\n", ret);
		return false;
	}

	wrapper->ffi_closures[wrapper->ffi_used] = clo;
	wrapper->ffi_used++;
	return true;
}

static bool
init_wrapper_funcs (Wrapper *wrapper)
{
	static const ffi_type *get_function_list_args[] = { &ffi_type_pointer, NULL };
	const FunctionInfo *info;
	CK_X_FUNCTION_LIST *over;
	void **bound;
	int i;

	/* Pointer to where our calls go */
	over = &wrapper->virt->funcs;

	for (i = 0; function_info[i].name != NULL; i++) {
		info = function_info + i;

		/* Address to where we're placing the bound function */
		bound = &STRUCT_MEMBER (void *, &wrapper->bound, info->module_offset);

		/*
		 * See if we can just shoot straight through to the module function
		 * without wrapping at all. If all the stacked virtual modules just
		 * fall through, then this returns the original module function.
		 */
		if (!lookup_fall_through (wrapper->virt, info, bound)) {
			if (!bind_ffi_closure (wrapper, over,
			                       info->binding_function,
			                       (ffi_type **)info->types, bound))
				return_val_if_reached (false);
		}
	}

	/* Always bind the C_GetFunctionList function itself */
	if (!bind_ffi_closure (wrapper, wrapper,
	                       binding_C_GetFunctionList,
	                       (ffi_type **)get_function_list_args,
	                       (void **)&wrapper->bound.C_GetFunctionList))
		return_val_if_reached (false);

	/*
	 * These functions are used as a marker to indicate whether this is
	 * one of our CK_FUNCTION_LIST_PTR sets of functions or not. These
	 * functions are defined to always have the same standard implementation
	 * in PKCS#11 2.x so we don't need to call through to the base for
	 * these guys.
	 */
	wrapper->bound.C_CancelFunction = short_C_CancelFunction;
	wrapper->bound.C_GetFunctionStatus = short_C_GetFunctionStatus;

	return true;
}

#if LIBFFI_FREE_CLOSURES
static void
uninit_wrapper_funcs (Wrapper *wrapper)
{
	int i;

	for (i = 0; i < wrapper->ffi_used; i++)
		ffi_closure_free (wrapper->ffi_closures[i]);
}
#endif

CK_FUNCTION_LIST *
p11_virtual_wrap (p11_virtual *virt,
                  p11_destroyer destroyer)
{
	Wrapper *wrapper;

	return_val_if_fail (virt != NULL, NULL);

	wrapper = calloc (1, sizeof (Wrapper));
	return_val_if_fail (wrapper != NULL, NULL);

	wrapper->virt = virt;
	wrapper->destroyer = destroyer;
	wrapper->bound.version.major = CRYPTOKI_VERSION_MAJOR;
	wrapper->bound.version.minor = CRYPTOKI_VERSION_MINOR;

	if (!init_wrapper_funcs (wrapper))
		return_val_if_reached (NULL);

	assert ((void *)wrapper == (void *)&wrapper->bound);
	assert (p11_virtual_is_wrapper (&wrapper->bound));
	assert (wrapper->bound.C_GetFunctionList != NULL);
	return &wrapper->bound;
}

bool
p11_virtual_can_wrap (void)
{
	return TRUE;
}

bool
p11_virtual_is_wrapper (CK_FUNCTION_LIST_PTR module)
{
	/*
	 * We use these functions as a marker to indicate whether this is
	 * one of our CK_FUNCTION_LIST_PTR sets of functions or not. These
	 * functions are defined to always have the same standard implementation
	 * in PKCS#11 2.x so we don't need to call through to the base for
	 * these guys.
	 */
	return (module->C_GetFunctionStatus == short_C_GetFunctionStatus &&
		module->C_CancelFunction == short_C_CancelFunction);
}

void
p11_virtual_unwrap (CK_FUNCTION_LIST_PTR module)
{
	Wrapper *wrapper;

	return_if_fail (p11_virtual_is_wrapper (module));

	/* The bound CK_FUNCTION_LIST_PTR sits at the front of Context */
	wrapper = (Wrapper *)module;

	/*
	 * Make sure that the CK_FUNCTION_LIST_PTR is invalid, and that
	 * p11_virtual_is_wrapper() recognizes this. This is in case the
	 * destroyer callback tries to do something fancy.
	 */
	memset (&wrapper->bound, 0xFE, sizeof (wrapper->bound));

	if (wrapper->destroyer)
		(wrapper->destroyer) (wrapper->virt);

#if LIBFFI_FREE_CLOSURES
	uninit_wrapper_funcs (wrapper);
#endif
	free (wrapper);
}

#else /* !WITH_FFI */

CK_FUNCTION_LIST *
p11_virtual_wrap (p11_virtual *virt,
                  p11_destroyer destroyer)
{
	assert_not_reached ();
}

bool
p11_virtual_can_wrap (void)
{
	return FALSE;
}

bool
p11_virtual_is_wrapper (CK_FUNCTION_LIST_PTR module)
{
	return FALSE;
}

void
p11_virtual_unwrap (CK_FUNCTION_LIST_PTR module)
{
	assert_not_reached ();
}

#endif /* !WITH_FFI */
