// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ocsp_internal.h"


/* get ocsp response status from |OCSP_RESPONSE| */
int OCSP_response_status(OCSP_RESPONSE *resp) {
  if (resp == NULL){
    OPENSSL_PUT_ERROR(OCSP, ERR_R_PASSED_NULL_PARAMETER);
    return -1;
  }
  return ASN1_ENUMERATED_get(resp->responseStatus);
}

/* Extract basic response from |OCSP_RESPONSE| */
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

