// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <openssl/evp.h>

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/mem.h>
#include <openssl/err.h>

#include "../internal.h"
#include "rsassa_pss.h"

const RSA_PSS_SUPPORTED_ALGOR sha1_func = {
    NID_sha1,
    // 1.3.14.3.2.26
    {0x2b, 0x0e, 0x03, 0x02, 0x1a},
    5,
};

const RSA_PSS_SUPPORTED_ALGOR sha224_func = {
    NID_sha224,
    // 2.16.840.1.101.3.4.2.4
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04},
    9,
};

const RSA_PSS_SUPPORTED_ALGOR sha256_func = {
    NID_sha256,
    // 2.16.840.1.101.3.4.2.1
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01},
    9,
};

const RSA_PSS_SUPPORTED_ALGOR sha384_func = {
    NID_sha384,
    // 2.16.840.1.101.3.4.2.2
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02},
    9,
};

const RSA_PSS_SUPPORTED_ALGOR sha512_func = {
    NID_sha512,
    // 2.16.840.1.101.3.4.2.3
    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03},
    9,
};

// Used to check if the oid is in the supported five hash functions.
// Section 2.1. https://tools.ietf.org/html/rfc4055#page-4
static const RSA_PSS_SUPPORTED_ALGOR *const rsa_pss_hash_functions[] = {
    &sha1_func, &sha224_func, &sha256_func, &sha384_func, &sha512_func,
};

const RSA_PSS_SUPPORTED_ALGOR MGF1 = {
    NID_mgf1,
    // 1.2.840.113549.1.1.8
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08},
    9,
};

// Used to check if the oid is in the supported mask generation functions.
// Section 2.2. https://tools.ietf.org/html/rfc4055#page-4
static const RSA_PSS_SUPPORTED_ALGOR *const rsa_pss_mg_functions[] = {
    &MGF1,
};

// parse_oid return one on success and zero on failure.
// Given |oid| and |supported_algors|, if match, set |*out| to be the algorithm
// identifier.
static int parse_oid(CBS *oid,
                     const RSA_PSS_SUPPORTED_ALGOR *const supported_algors[],
                     size_t size, RSA_ALGOR_IDENTIFIER **out) {
  for (size_t i = 0; i < size; i++) {
    const RSA_PSS_SUPPORTED_ALGOR *supported_algr = supported_algors[i];
    if (CBS_len(oid) == supported_algr->oid_len &&
        OPENSSL_memcmp(CBS_data(oid), supported_algr->oid,
                       supported_algr->oid_len) == 0) {
      *out = RSA_ALGOR_IDENTIFIER_new();
      if (*out != NULL) {
        (*out)->nid = supported_algr->nid;
      }
      return (*out) != NULL;
    }
  }
  OPENSSL_PUT_ERROR(RSA, EVP_R_UNSUPPORTED_ALGORITHM);
  return 0;
}

// For One-way Hash Functions:
// All implementations MUST accept both NULL and absent parameters as legal and
// equivalent encodings. See 2.1. https://tools.ietf.org/html/rfc4055#page-5
static int is_absent_or_null(CBS *params) {
  CBS null;
  return (CBS_len(params) == 0) ||
         (CBS_get_asn1(params, &null, CBS_ASN1_NULL) && (CBS_len(&null) == 0) &&
          (CBS_len(params) == 0));
}

// Decode One-way Hash Functions: return one on success and zero on failure.
// See 2.1. https://tools.ietf.org/html/rfc4055#page-5
static int decode_one_way_hash(CBS *cbs, RSA_ALGOR_IDENTIFIER **hash_algor) {
  CBS seq, oid;
  if (CBS_get_asn1(cbs, &seq, CBS_ASN1_SEQUENCE) && (CBS_len(cbs) == 0) &&
      CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT) && is_absent_or_null(&seq) &&
      parse_oid(&oid, rsa_pss_hash_functions,
                OPENSSL_ARRAY_SIZE(rsa_pss_hash_functions), hash_algor)) {
    return 1;
  }
  OPENSSL_PUT_ERROR(RSA, EVP_R_DECODE_ERROR);
  return 0;
}

// Decode Mask Generation Functions: return one on success and zero on failure.
// See 2.2. https://tools.ietf.org/html/rfc4055#page-5
static int decode_mask_gen(CBS *cbs, RSA_MGA_IDENTIFIER **mga) {
  CBS seq, mgf1_oid, hash_seq, hash_oid;
  RSA_ALGOR_IDENTIFIER *mgf1 = NULL;
  RSA_ALGOR_IDENTIFIER *hash_algor = NULL;
  if (CBS_get_asn1(cbs, &seq, CBS_ASN1_SEQUENCE) && (CBS_len(cbs) == 0) &&
      CBS_get_asn1(&seq, &mgf1_oid, CBS_ASN1_OBJECT) &&
      CBS_get_asn1(&seq, &hash_seq, CBS_ASN1_SEQUENCE) &&
      (CBS_len(&seq) == 0) &&
      CBS_get_asn1(&hash_seq, &hash_oid, CBS_ASN1_OBJECT) &&
      is_absent_or_null(&hash_seq) &&
      parse_oid(&mgf1_oid, rsa_pss_mg_functions,
                OPENSSL_ARRAY_SIZE(rsa_pss_mg_functions), &mgf1) &&
      parse_oid(&hash_oid, rsa_pss_hash_functions,
                OPENSSL_ARRAY_SIZE(rsa_pss_hash_functions), &hash_algor)) {
    *mga = RSA_MGA_IDENTIFIER_new();
    if (*mga != NULL) {
      (*mga)->mask_gen = mgf1;
      (*mga)->one_way_hash = hash_algor;
      return 1;
    }
  }
  OPENSSL_PUT_ERROR(RSA, EVP_R_DECODE_ERROR);
  RSA_ALGOR_IDENTIFIER_free(mgf1);
  RSA_ALGOR_IDENTIFIER_free(hash_algor);
  return 0;
}

// get_context_specific_value sets |*out| to the contents of DER-encoded, ASN.1
// element (not including tag and length bytes) and advances |seq| over it.
// When the tag value does not exist, |seq| gets recovered.
// It returns one when the element exists.
static int get_context_specific_value(CBS *seq, CBS *out, int index) {
  unsigned int tag_value = CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | index;
  CBS seq_cp = {seq->data, seq->len};
  if (CBS_get_asn1(seq, out, tag_value)) {
    return 1;
  } else {
    // All fields of RSASSA-PSS-params can be absent, which means default.
    // Recover |seq|.
    seq->data = seq_cp.data;
    seq->len = seq_cp.len;
    return 0;
  }
}

// Decode [0] HashAlgorithm of RSASSA-PSS-params: return one on success and zero
// on failure. See 3.1. https://tools.ietf.org/html/rfc4055#page-7
static int decode_pss_hash(CBS *seq, RSA_ALGOR_IDENTIFIER **hash_algor) {
  CBS cs;
  if (!get_context_specific_value(seq, &cs, 0)) {
    // HashAlgorithm field can be absent, which means default.
    return 1;
  }
  return decode_one_way_hash(&cs, hash_algor);
}

// Decode [1] MaskGenAlgorithm of RSASSA-PSS-params: return one on success and
// zero on failure. See 3.1. https://tools.ietf.org/html/rfc4055#page-7
static int decode_pss_mask_gen(CBS *seq, RSA_MGA_IDENTIFIER **mga) {
  CBS cs;
  if (!get_context_specific_value(seq, &cs, 1)) {
    // MaskGenAlgorithm field can be absent, which means default.
    return 1;
  }
  return decode_mask_gen(&cs, mga);
}

static int parse_rsa_int(CBS *cbs, RSA_INTEGER **rsa_int) {
  int64_t value = 0;
  if (CBS_get_asn1_int64(cbs, &value) && CBS_len(cbs) == 0) {
    *rsa_int = RSA_INTEGER_new();
    if ((*rsa_int) != NULL) {
      (*rsa_int)->value = value;
      return 1;
    }
  }
  OPENSSL_PUT_ERROR(RSA, EVP_R_DECODE_ERROR);
  return 0;
}

// Decode [2] saltLength of RSASSA-PSS-params
// See 3.1. https://tools.ietf.org/html/rfc4055#page-7
static int decode_pss_salt_len(CBS *seq, RSA_INTEGER **salt_len) {
  CBS cs;
  if (!get_context_specific_value(seq, &cs, 2)) {
    // saltLength field can be absent, which means default.
    return 1;
  }
  return parse_rsa_int(&cs, salt_len);
}

// Decode [3] trailerField of RSASSA-PSS-params
// See 3.1. https://tools.ietf.org/html/rfc4055#page-7
static int decode_pss_trailer_field(CBS *seq, RSA_INTEGER **trailer_field) {
  CBS cs;
  if (!get_context_specific_value(seq, &cs, 3)) {
    // Trailer field can be absent, which means default.
    return 1;
  }
  return parse_rsa_int(&cs, trailer_field);
}

// Get RSASSA-PSS-params sequence
// See 3.1. https://tools.ietf.org/html/rfc4055#page-7
int RSASSA_PSS_parse_params(CBS *params, RSASSA_PSS_PARAMS **pss_params) {
  if (CBS_len(params) == 0) {
    // The parameters may be either absent.
    return 1;
  }
  RSA_ALGOR_IDENTIFIER *hash_algor = NULL;
  RSA_MGA_IDENTIFIER *mask_gen_algor = NULL;
  RSA_INTEGER *salt_len = NULL;
  RSA_INTEGER *trailer_field = NULL;
  CBS seq;
  if (CBS_get_asn1(params, &seq, CBS_ASN1_SEQUENCE) && (CBS_len(params) == 0) &&
      decode_pss_hash(&seq, &hash_algor) &&
      decode_pss_mask_gen(&seq, &mask_gen_algor) &&
      decode_pss_salt_len(&seq, &salt_len) &&
      decode_pss_trailer_field(&seq, &trailer_field) && (CBS_len(&seq) == 0)) {
    *pss_params = RSASSA_PSS_PARAMS_new();
    if ((*pss_params) != NULL) {
      (*pss_params)->hash_algor = hash_algor;
      (*pss_params)->mask_gen_algor = mask_gen_algor;
      (*pss_params)->salt_len = salt_len;
      (*pss_params)->trailer_field = trailer_field;
      return 1;
    }
  }
  RSA_ALGOR_IDENTIFIER_free(hash_algor);
  RSA_MGA_IDENTIFIER_free(mask_gen_algor);
  RSA_INTEGER_free(salt_len);
  RSA_INTEGER_free(trailer_field);
  return 0;
}

RSA_INTEGER *RSA_INTEGER_new(void) {
  RSA_INTEGER *ret = OPENSSL_malloc(sizeof(RSA_INTEGER));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(RSA_INTEGER));
  return ret;
}

RSA_ALGOR_IDENTIFIER *RSA_ALGOR_IDENTIFIER_new(void) {
  RSA_ALGOR_IDENTIFIER *ret = OPENSSL_malloc(sizeof(RSA_ALGOR_IDENTIFIER));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(RSA_ALGOR_IDENTIFIER));
  return ret;
}

RSA_MGA_IDENTIFIER *RSA_MGA_IDENTIFIER_new(void) {
  RSA_MGA_IDENTIFIER *ret = OPENSSL_malloc(sizeof(RSA_MGA_IDENTIFIER));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(RSA_MGA_IDENTIFIER));
  return ret;
}

RSASSA_PSS_PARAMS *RSASSA_PSS_PARAMS_new(void) {
  RSASSA_PSS_PARAMS *ret = OPENSSL_malloc(sizeof(RSASSA_PSS_PARAMS));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(RSASSA_PSS_PARAMS));
  return ret;
}

void RSA_INTEGER_free(RSA_INTEGER *ptr) {
  OPENSSL_free(ptr);
}

void RSA_ALGOR_IDENTIFIER_free(RSA_ALGOR_IDENTIFIER *algor) {
  OPENSSL_free(algor);
}

void RSA_MGA_IDENTIFIER_free(RSA_MGA_IDENTIFIER *mga) {
  if (mga == NULL) {
    return;
  }
  RSA_ALGOR_IDENTIFIER_free(mga->mask_gen);
  RSA_ALGOR_IDENTIFIER_free(mga->one_way_hash);
  OPENSSL_free(mga);
}

void RSASSA_PSS_PARAMS_free(RSASSA_PSS_PARAMS *params) {
  if (params == NULL) {
    return;
  }
  RSA_ALGOR_IDENTIFIER_free(params->hash_algor);
  RSA_MGA_IDENTIFIER_free(params->mask_gen_algor);
  RSA_INTEGER_free(params->salt_len);
  RSA_INTEGER_free(params->trailer_field);
  OPENSSL_free(params);
}