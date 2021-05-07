// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ocsp_internal.h"

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject,
                             const X509 *issuer)
{
  if (issuer == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  const X509_NAME *iname;
  const ASN1_INTEGER *serial;
  ASN1_BIT_STRING *ikey;

  if (dgst == NULL) {
    dgst = EVP_sha1();
  }
  if (subject != NULL) {
    iname = X509_get_issuer_name(subject);
    serial = X509_get0_serialNumber(subject);
  } else {
    iname = X509_get_subject_name(issuer);
    serial = NULL;
  }
  ikey = X509_get0_pubkey_bitstr(issuer);
  return OCSP_cert_id_new(dgst, iname, ikey, serial);
}

OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst,
                              const X509_NAME *issuerName,
                              const ASN1_BIT_STRING *issuerKey,
                              const ASN1_INTEGER *serialNumber)
{
  if(dgst == NULL || issuerName == NULL || issuerKey == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  int nid;
  unsigned int i;
  X509_ALGOR *alg;
  OCSP_CERTID *cid = NULL;
  unsigned char md[EVP_MAX_MD_SIZE];

  if ((cid = OCSP_CERTID_new()) == NULL) {
    goto err;
  }

  alg = cid->hashAlgorithm;
  ASN1_OBJECT_free(alg->algorithm);
  if ((nid = EVP_MD_type(dgst)) == NID_undef) {
    OPENSSL_PUT_ERROR(OCSP, OCSP_R_UNKNOWN_NID);
    goto err;
  }
  if ((alg->algorithm = OBJ_nid2obj(nid)) == NULL) {
    goto err;
  }
  if ((alg->parameter = ASN1_TYPE_new()) == NULL) {
    goto err;
  }
  alg->parameter->type = V_ASN1_NULL;

  if (!X509_NAME_digest(issuerName, dgst, md, &i)) {
    OPENSSL_PUT_ERROR(OCSP, OCSP_R_DIGEST_ERR);
    goto err;
  }
  if (!(ASN1_OCTET_STRING_set(cid->issuerNameHash, md, i))) {
    goto err;
  }
  /* Calculate the issuerKey hash, excluding tag and length */
  if (!EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst, NULL)) {
    goto err;
  }
  if (!(ASN1_OCTET_STRING_set(cid->issuerKeyHash, md, i))) {
    goto err;
  }

  if (serialNumber != NULL) {
    if (ASN1_STRING_copy(cid->serialNumber, serialNumber) == 0)
      goto err;
  }
  return cid;
  err:
  OCSP_CERTID_free(cid);
  return NULL;
}

int OCSP_id_issuer_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)
{
  if (a == NULL || b == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  int ret = OBJ_cmp(a->hashAlgorithm->algorithm, b->hashAlgorithm->algorithm);
  if (ret != 0) return ret;
  ret = ASN1_OCTET_STRING_cmp(a->issuerNameHash, b->issuerNameHash);
  if (ret != 0) return ret;
  ret = ASN1_OCTET_STRING_cmp(a->issuerKeyHash, b->issuerKeyHash);
  return ret;
}

int OCSP_id_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)
{
  if (a == NULL || b == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  int ret = OCSP_id_issuer_cmp(a, b);
  if (ret != 0) return ret;
  ret = ASN1_INTEGER_cmp(a->serialNumber, b->serialNumber);
  return ret;
}
