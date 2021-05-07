/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef AWSLC_OCSP_H
#define AWSLC_OCSP_H

#include <openssl/asn1t.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ocsp_cert_id_st OCSP_CERTID;
typedef struct ocsp_responder_id_st OCSP_RESPID;
typedef struct ocsp_signature_st OCSP_SIGNATURE;
typedef struct ocsp_resp_bytes_st OCSP_RESPBYTES;
typedef struct ocsp_revoked_info_st OCSP_REVOKEDINFO;
typedef struct ocsp_cert_status_st OCSP_CERTSTATUS;
typedef struct ocsp_single_response_st OCSP_SINGLERESP;
typedef struct ocsp_response_data_st OCSP_RESPDATA;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_basic_response_st OCSP_BASICRESP;

DEFINE_STACK_OF(OCSP_CERTID)
DEFINE_STACK_OF(OCSP_RESPID)
DEFINE_STACK_OF(OCSP_SINGLERESP)

DECLARE_ASN1_FUNCTIONS(OCSP_SINGLERESP)
DECLARE_ASN1_FUNCTIONS(OCSP_CERTSTATUS)
DECLARE_ASN1_FUNCTIONS(OCSP_REVOKEDINFO)
DECLARE_ASN1_FUNCTIONS(OCSP_BASICRESP)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPDATA)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPID)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPONSE)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPBYTES)
DECLARE_ASN1_FUNCTIONS(OCSP_CERTID)
DECLARE_ASN1_FUNCTIONS(OCSP_SIGNATURE)

/* Returns response status from |OCSP_RESPONSE| */
OPENSSL_EXPORT int OCSP_response_status(OCSP_RESPONSE *resp);

/* Returns |OCSP_BASICRESP| from |OCSP_RESPONSE| */
OPENSSL_EXPORT OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp);

/* Returns |OCSP_SINGLERESP| in the index of |OCSP_BASICRESP| */
OPENSSL_EXPORT OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, size_t idx);

/*
 * Returns index of |OCSP_SINGLERESP| in |OCSP_BASICRESP| matching a given certificate ID,
 * Returns -1 if not found
 */
OPENSSL_EXPORT int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last);

/*
 * Returns status of |OCSP_SINGLERESP|
 * Note:
 *  1. Reason value is allowed to be null
 *  2. Time values passed into function are allowed to be NULL if certificate
 *     fields are empty.
 *  3. revtime and reason values only set if the certificate status is revoked.
 */
OPENSSL_EXPORT int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason,
                            ASN1_GENERALIZEDTIME **revtime,
                            ASN1_GENERALIZEDTIME **thisupd,
                            ASN1_GENERALIZEDTIME **nextupd);

/* Looks up a cert id and extract status information if found, Returns 1 on success. */
OPENSSL_EXPORT int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
                          int *reason,
                          ASN1_GENERALIZEDTIME **revtime,
                          ASN1_GENERALIZEDTIME **thisupd,
                          ASN1_GENERALIZEDTIME **nextupd);

/* Returns a |OCSP_CERTID| converted from a certificate and its issuer */
OPENSSL_EXPORT OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject,
                                            const X509 *issuer);

OPENSSL_EXPORT OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst,
                                             const X509_NAME *issuerName,
                                             const ASN1_BIT_STRING *issuerKey,
                                             const ASN1_INTEGER *serialNumber);

/* --- OCSP compare functions --- */
/* Compares certificate id issuers, Returns 0 on equal. */
OPENSSL_EXPORT int OCSP_id_issuer_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b);

/* Compares certificate id, Returns 0 on equal. */
OPENSSL_EXPORT int OCSP_id_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b);

#ifdef __cplusplus
}
#endif

#if !defined(BORINGSSL_NO_CXX)
extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(OCSP_RESPONSE, OCSP_RESPONSE_free)
BORINGSSL_MAKE_DELETER(OCSP_BASICRESP, OCSP_BASICRESP_free)
BORINGSSL_MAKE_DELETER(OCSP_CERTID, OCSP_CERTID_free)

BSSL_NAMESPACE_END

}  // extern C++
#endif  // !BORINGSSL_NO_CXX

#define OCSP_RESPONSE_STATUS_SUCCESSFUL           0
#define OCSP_RESPONSE_STATUS_MALFORMEDREQUEST     1
#define OCSP_RESPONSE_STATUS_INTERNALERROR        2
#define OCSP_RESPONSE_STATUS_TRYLATER             3
#define OCSP_RESPONSE_STATUS_SIGREQUIRED          5
#define OCSP_RESPONSE_STATUS_UNAUTHORIZED         6

#define V_OCSP_CERTSTATUS_GOOD                    0
#define V_OCSP_CERTSTATUS_REVOKED                 1
#define V_OCSP_CERTSTATUS_UNKNOWN                 2

#define OCSP_R_DIGEST_ERR                         102
#define OCSP_R_NOT_BASIC_RESPONSE                 104
#define OCSP_R_NO_RESPONSE_DATA                   108
#define OCSP_R_UNKNOWN_NID                        120

#endif  // AWSLC_OCSP_H
