// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ocsp_internal.h"


int OCSP_response_status(OCSP_RESPONSE *resp) {
  if (resp == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }
  return ASN1_ENUMERATED_get(resp->responseStatus);
}

OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp) {
  if (resp == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  OCSP_RESPBYTES *rb = resp->responseBytes;
  if (rb == NULL) {
    OPENSSL_PUT_ERROR(OCSP, OCSP_R_NO_RESPONSE_DATA);
    return NULL;
  }
  if (OBJ_obj2nid(rb->responseType) != NID_id_pkix_OCSP_basic) {
    OPENSSL_PUT_ERROR(OCSP, OCSP_R_NOT_BASIC_RESPONSE);
    return NULL;
  }
  return ASN1_item_unpack(rb->response, ASN1_ITEM_rptr(OCSP_BASICRESP));
}

OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, size_t idx)
{
  if (bs == NULL) {
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }
  return sk_OCSP_SINGLERESP_value(bs->tbsResponseData->responses, idx);
}

int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last)
{
  if (bs == NULL || id == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  STACK_OF(OCSP_SINGLERESP) *sresp = bs->tbsResponseData->responses;
  OCSP_SINGLERESP *single;

  if (last < 0) {
    last = 0;
  } else {
    last++;
  }
  for (size_t i = last; i < sk_OCSP_SINGLERESP_num(sresp); i++) {
    single = sk_OCSP_SINGLERESP_value(sresp, i);
    if (!OCSP_id_cmp(id, single->certId)) {
      return i;
    }
  }
  return -1;
}

int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason,
                            ASN1_GENERALIZEDTIME **revtime,
                            ASN1_GENERALIZEDTIME **thisupd,
                            ASN1_GENERALIZEDTIME **nextupd) {
  if (single == NULL) {
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  OCSP_CERTSTATUS *cst = single->certStatus;
  int status = cst->type;
  /*
   * If certificate status is revoked, we look up certificate revocation
   * time and reason
   */
  if (status == V_OCSP_CERTSTATUS_REVOKED) {
    OCSP_REVOKEDINFO *rev = cst->value.revoked;
    if (revtime != NULL) {
      *revtime = rev->revocationTime;
    }
    if (reason != NULL) {
      if (rev->revocationReason) {
        *reason = ASN1_ENUMERATED_get(rev->revocationReason);
      } else {
        *reason = -1;
      }
    }
  }
  /*
   * Look up when certificate was last updated and when is next update time
   */
  if (thisupd != NULL) {
    *thisupd = single->thisUpdate;
  }
  if (nextupd != NULL) {
    *nextupd = single->nextUpdate;
  }
  return status;
}

int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
                          int *reason,
                          ASN1_GENERALIZEDTIME **revtime,
                          ASN1_GENERALIZEDTIME **thisupd,
                          ASN1_GENERALIZEDTIME **nextupd) {
  if (bs == NULL || id == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }

  int single_idx = OCSP_resp_find(bs, id, -1);
  if (single_idx < 0) {
    return 0;
  }
  OCSP_SINGLERESP *single = OCSP_resp_get0(bs, single_idx);

  int single_status = OCSP_single_get0_status(single, reason, revtime, thisupd, nextupd);
  if (status != NULL) {
    *status = single_status;
  }
  return 1;
}
