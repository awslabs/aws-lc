/*
------------------------------------------------------------------------------------
 Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: Apache-2.0
------------------------------------------------------------------------------------
*/

// Implementation of P-384 that uses Fiat-crypto for the field arithmetic
// found in third_party/fiat, similarly to p256.c

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../bn/internal.h"
#include "../delocate.h"
#include "internal.h"

#if defined(BORINGSSL_HAS_UINT128)
#define BORINGSSL_NISTP384_64BIT 1
#include "../../../third_party/fiat/p384_64.h"
#else
#include "../../../third_party/fiat/p384_32.h"
#endif

#if defined(BORINGSSL_NISTP384_64BIT)
#define FIAT_P384_NLIMBS 6
typedef uint64_t fiat_p384_limb_t;
typedef uint64_t fiat_p384_felem[FIAT_P384_NLIMBS];
static const fiat_p384_felem fiat_p384_one = {0xffffffff00000001, 0xffffffff,
                                              0x1, 0x0, 0x0, 0x0};
#else  // 64BIT; else 32BIT
#define FIAT_P384_NLIMBS 12
typedef uint32_t fiat_p384_limb_t;
typedef uint32_t fiat_p384_felem[FIAT_P384_NLIMBS];
static const fiat_p384_felem fiat_p384_one = {
    0x1, 0xffffffff, 0xffffffff, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
#endif  // 64BIT

static fiat_p384_limb_t fiat_p384_nz(
    const fiat_p384_limb_t in1[FIAT_P384_NLIMBS]) {
  fiat_p384_limb_t ret;
  fiat_p384_nonzero(&ret, in1);
  return ret;
}

static void fiat_p384_copy(fiat_p384_limb_t out[FIAT_P384_NLIMBS],
                           const fiat_p384_limb_t in1[FIAT_P384_NLIMBS]) {
  for (size_t i = 0; i < FIAT_P384_NLIMBS; i++) {
    out[i] = in1[i];
  }
}

static void fiat_p384_cmovznz(fiat_p384_limb_t out[FIAT_P384_NLIMBS],
                              fiat_p384_limb_t t,
                              const fiat_p384_limb_t z[FIAT_P384_NLIMBS],
                              const fiat_p384_limb_t nz[FIAT_P384_NLIMBS]) {
  fiat_p384_selectznz(out, !!t, z, nz);
}

static void fiat_p384_from_generic(fiat_p384_felem out, const EC_FELEM *in) {
  fiat_p384_from_bytes(out, in->bytes);
}

static void fiat_p384_to_generic(EC_FELEM *out, const fiat_p384_felem in) {
  // This works because 384 is a multiple of 64, so there are no excess bytes to
  // zero when rounding up to |BN_ULONG|s.
  OPENSSL_STATIC_ASSERT(
      384 / 8 == sizeof(BN_ULONG) * ((384 + BN_BITS2 - 1) / BN_BITS2),
      fiat_p384_to_bytes_leaves_bytes_uninitialized);
  fiat_p384_to_bytes(out->bytes, in);
}

// fiat_p384_inv_square calculates |out| = |in|^{-2}
//
// Based on Fermat's Little Theorem:
//   a^p = a (mod p)
//   a^{p-1} = 1 (mod p)
//   a^{p-3} = a^{-2} (mod p)
// p = 2^384 - 2^128 - 2^96 + 2^32 - 1
// Hexadecimal representation of p − 3:
// p-3 = ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe
//       ffffffff 00000000 00000000 fffffffc
static void fiat_p384_inv_square(fiat_p384_felem out,
                                 const fiat_p384_felem in) {
  // This implements the addition chain described in
  // https://briansmith.org/ecc-inversion-addition-chains-01#p384_field_inversion
  // The side comments show the value of the exponent:
  // squaring the element => doubling the exponent
  // multiplying by an element => adding to the exponent the power of that element
  fiat_p384_felem x2, x3, x6, x12, x15, x30, x60, x120;
  fiat_p384_square(x2, in);   // 2^2 - 2^1
  fiat_p384_mul(x2, x2, in);  // 2^2 - 2^0

  fiat_p384_square(x3, x2);   // 2^3 - 2^1
  fiat_p384_mul(x3, x3, in);  // 2^3 - 2^0

  fiat_p384_square(x6, x3);
  for (int i = 1; i < 3; i++) {
    fiat_p384_square(x6, x6);
  }                           // 2^6 - 2^3
  fiat_p384_mul(x6, x6, x3);  // 2^6 - 2^0

  fiat_p384_square(x12, x6);
  for (int i = 1; i < 6; i++) {
    fiat_p384_square(x12, x12);
  }                             // 2^12 - 2^6
  fiat_p384_mul(x12, x12, x6);  // 2^12 - 2^0

  fiat_p384_square(x15, x12);
  for (int i = 1; i < 3; i++) {
    fiat_p384_square(x15, x15);
  }                             // 2^15 - 2^3
  fiat_p384_mul(x15, x15, x3);  // 2^15 - 2^0

  fiat_p384_square(x30, x15);
  for (int i = 1; i < 15; i++) {
    fiat_p384_square(x30, x30);
  }                              // 2^30 - 2^15
  fiat_p384_mul(x30, x30, x15);  // 2^30 - 2^0

  fiat_p384_square(x60, x30);
  for (int i = 1; i < 30; i++) {
    fiat_p384_square(x60, x60);
  }                              // 2^60 - 2^30
  fiat_p384_mul(x60, x60, x30);  // 2^60 - 2^0

  fiat_p384_square(x120, x60);
  for (int i = 1; i < 60; i++) {
    fiat_p384_square(x120, x120);
  }                                // 2^120 - 2^60
  fiat_p384_mul(x120, x120, x60);  // 2^120 - 2^0

  fiat_p384_felem ret;
  fiat_p384_square(ret, x120);
  for (int i = 1; i < 120; i++) {
    fiat_p384_square(ret, ret);
  }                                // 2^240 - 2^120
  fiat_p384_mul(ret, ret, x120);   // 2^240 - 2^0

  for (int i = 0; i < 15; i++) {
    fiat_p384_square(ret, ret);
  }                                // 2^255 - 2^15
  fiat_p384_mul(ret, ret, x15);    // 2^255 - 2^0

  // Why (1 + 30) in the loop?
  // This is as expressed in https://briansmith.org/ecc-inversion-addition-chains-01#p384_field_inversion
  // My guess is to say that we're going to shift 31 bits, but this time we won't add x31
  // to make all the new bits 1s, as was done in previous steps,
  // but we're going to add x30 so there will be 255 1s, then a 0, then 30 1s to form this pattern:
  // ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff
  // (the last 2 1s are appended in the following step).
  for (int i = 0; i < (1 + 30); i++) {
    fiat_p384_square(ret, ret);
  }                                // 2^286 - 2^31
  fiat_p384_mul(ret, ret, x30);    // 2^286 - 2^30 - 2^0

  fiat_p384_square(ret, ret);
  fiat_p384_square(ret, ret);      // 2^288 - 2^32 - 2^2
  fiat_p384_mul(ret, ret, x2);     // 2^288 - 2^32 - 2^0

  // Why not 94 instead of (64 + 30) in the loop?
  // Similarly to the comment above, there is a shift of 94 bits but what will be added is x30,
  // which will cause 64 of those bits to be 64 0s and 30 1s to complete the pattern above with:
  // 00000000 00000000 fffffffc
  // (the last 2 0s are appended by the last 2 shifts).
  for (int i = 0; i < (64 + 30); i++) {
    fiat_p384_square(ret, ret);
  }                                // 2^382 - 2^126 - 2^94
  fiat_p384_mul(ret, ret, x30);    // 2^382 - 2^126 - 2^94 + 2^30 - 2^0

  fiat_p384_square(ret, ret);
  fiat_p384_square(out, ret);      // 2^384 - 2^128 - 2^96 + 2^32 - 2^2 = p - 3
}

// Group operations
// ----------------
//
// Building on top of the field operations we have the operations on the
// elliptic curve group itself. Points on the curve are represented in Jacobian
// coordinates.
//
// fiat_p384_point_double calculates 2*(x_in, y_in, z_in)
//
// The method is taken from:
//   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
//
// Coq transcription and correctness proof:
// <https://github.com/mit-plv/fiat-crypto/blob/79f8b5f39ed609339f0233098dee1a3c4e6b3080/src/Curves/Weierstrass/Jacobian.v#L93>
// <https://github.com/mit-plv/fiat-crypto/blob/79f8b5f39ed609339f0233098dee1a3c4e6b3080/src/Curves/Weierstrass/Jacobian.v#L201>
// Outputs can equal corresponding inputs, i.e., x_out == x_in is allowed;
// while x_out == y_in is not (maybe this works, but it's not tested).
static void fiat_p384_point_double(fiat_p384_felem x_out, fiat_p384_felem y_out,
                                   fiat_p384_felem z_out,
                                   const fiat_p384_felem x_in,
                                   const fiat_p384_felem y_in,
                                   const fiat_p384_felem z_in) {
  fiat_p384_felem delta, gamma, beta, ftmp, ftmp2, tmptmp, alpha, fourbeta;
  // delta = z^2
  fiat_p384_square(delta, z_in);
  // gamma = y^2
  fiat_p384_square(gamma, y_in);
  // beta = x*gamma
  fiat_p384_mul(beta, x_in, gamma);

  // alpha = 3*(x-delta)*(x+delta)
  fiat_p384_sub(ftmp, x_in, delta);
  fiat_p384_add(ftmp2, x_in, delta);

  fiat_p384_add(tmptmp, ftmp2, ftmp2);
  fiat_p384_add(ftmp2, ftmp2, tmptmp);
  fiat_p384_mul(alpha, ftmp, ftmp2);

  // x' = alpha^2 - 8*beta
  fiat_p384_square(x_out, alpha);
  fiat_p384_add(fourbeta, beta, beta);
  fiat_p384_add(fourbeta, fourbeta, fourbeta);
  fiat_p384_add(tmptmp, fourbeta, fourbeta);
  fiat_p384_sub(x_out, x_out, tmptmp);

  // z' = (y + z)^2 - gamma - delta
  // The following calculation differs from that in p256.c:
  // An add is replaced with a sub in order to save 5 cmovznz.
  fiat_p384_add(ftmp, y_in, z_in);
  fiat_p384_square(z_out, ftmp);
  fiat_p384_sub(z_out, z_out, gamma);
  fiat_p384_sub(z_out, z_out, delta);

  // y' = alpha*(4*beta - x') - 8*gamma^2
  fiat_p384_sub(y_out, fourbeta, x_out);
  fiat_p384_add(gamma, gamma, gamma);
  fiat_p384_square(gamma, gamma);
  fiat_p384_mul(y_out, alpha, y_out);
  fiat_p384_add(gamma, gamma, gamma);
  fiat_p384_sub(y_out, y_out, gamma);
}

// fiat_p384_point_add calculates (x1, y1, z1) + (x2, y2, z2)
//
// The method is taken from:
//   http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
// adapted for mixed addition (z2 = 1, or z2 = 0 for the point at infinity).
//
// Coq transcription and correctness proof:
// <https://github.com/davidben/fiat-crypto/blob/c7b95f62b2a54b559522573310e9b487327d219a/src/Curves/Weierstrass/Jacobian.v#L467>
// <https://github.com/davidben/fiat-crypto/blob/c7b95f62b2a54b559522573310e9b487327d219a/src/Curves/Weierstrass/Jacobian.v#L544>
static void fiat_p384_point_add(fiat_p384_felem x3, fiat_p384_felem y3,
                                fiat_p384_felem z3, const fiat_p384_felem x1,
                                const fiat_p384_felem y1,
                                const fiat_p384_felem z1, const int mixed,
                                const fiat_p384_felem x2,
                                const fiat_p384_felem y2,
                                const fiat_p384_felem z2) {
  fiat_p384_felem x_out, y_out, z_out;
  fiat_p384_limb_t z1nz = fiat_p384_nz(z1);
  fiat_p384_limb_t z2nz = fiat_p384_nz(z2);

  // z1z1 = z1z1 = z1**2
  fiat_p384_felem z1z1;
  fiat_p384_square(z1z1, z1);

  fiat_p384_felem u1, s1, two_z1z2;
  if (!mixed) {
    // z2z2 = z2**2
    fiat_p384_felem z2z2;
    fiat_p384_square(z2z2, z2);

    // u1 = x1*z2z2
    fiat_p384_mul(u1, x1, z2z2);

    // two_z1z2 = (z1 + z2)**2 - (z1z1 + z2z2) = 2z1z2
    fiat_p384_add(two_z1z2, z1, z2);
    fiat_p384_square(two_z1z2, two_z1z2);
    fiat_p384_sub(two_z1z2, two_z1z2, z1z1);
    fiat_p384_sub(two_z1z2, two_z1z2, z2z2);

    // s1 = y1 * z2**3
    fiat_p384_mul(s1, z2, z2z2);
    fiat_p384_mul(s1, s1, y1);
  } else {
    // We'll assume z2 = 1 (special case z2 = 0 is handled later).

    // u1 = x1*z2z2
    fiat_p384_copy(u1, x1);
    // two_z1z2 = 2z1z2
    fiat_p384_add(two_z1z2, z1, z1);
    // s1 = y1 * z2**3
    fiat_p384_copy(s1, y1);
  }

  // u2 = x2*z1z1
  fiat_p384_felem u2;
  fiat_p384_mul(u2, x2, z1z1);

  // h = u2 - u1
  fiat_p384_felem h;
  fiat_p384_sub(h, u2, u1);

  fiat_p384_limb_t xneq = fiat_p384_nz(h);

  // z_out = two_z1z2 * h
  fiat_p384_mul(z_out, h, two_z1z2);

  // z1z1z1 = z1 * z1z1
  fiat_p384_felem z1z1z1;
  fiat_p384_mul(z1z1z1, z1, z1z1);

  // s2 = y2 * z1**3
  fiat_p384_felem s2;
  fiat_p384_mul(s2, y2, z1z1z1);

  // r = (s2 - s1)*2
  fiat_p384_felem r;
  fiat_p384_sub(r, s2, s1);
  fiat_p384_add(r, r, r);

  fiat_p384_limb_t yneq = fiat_p384_nz(r);

  // This case will never occur in the constant-time |ec_GFp_mont_mul|.
  fiat_p384_limb_t is_nontrivial_double = constant_time_is_zero_w(xneq | yneq) &
                                          ~constant_time_is_zero_w(z1nz) &
                                          ~constant_time_is_zero_w(z2nz);
  if (is_nontrivial_double) {
    fiat_p384_point_double(x3, y3, z3, x1, y1, z1);
    return;
  }

  // I = (2h)**2
  fiat_p384_felem i;
  fiat_p384_add(i, h, h);
  fiat_p384_square(i, i);

  // J = h * I
  fiat_p384_felem j;
  fiat_p384_mul(j, h, i);

  // V = U1 * I
  fiat_p384_felem v;
  fiat_p384_mul(v, u1, i);

  // x_out = r**2 - J - 2V
  fiat_p384_square(x_out, r);
  fiat_p384_sub(x_out, x_out, j);
  fiat_p384_sub(x_out, x_out, v);
  fiat_p384_sub(x_out, x_out, v);

  // y_out = r(V-x_out) - 2 * s1 * J
  fiat_p384_sub(y_out, v, x_out);
  fiat_p384_mul(y_out, y_out, r);
  fiat_p384_felem s1j;
  fiat_p384_mul(s1j, s1, j);
  fiat_p384_sub(y_out, y_out, s1j);
  fiat_p384_sub(y_out, y_out, s1j);

  fiat_p384_cmovznz(x_out, z1nz, x2, x_out);
  fiat_p384_cmovznz(x3, z2nz, x1, x_out);
  fiat_p384_cmovznz(y_out, z1nz, y2, y_out);
  fiat_p384_cmovznz(y3, z2nz, y1, y_out);
  fiat_p384_cmovznz(z_out, z1nz, z2, z_out);
  fiat_p384_cmovznz(z3, z2nz, z1, z_out);
}

// OPENSSL EC_METHOD FUNCTIONS

// Takes the Jacobian coordinates (X, Y, Z) of a point and returns (X', Y') =
// (X/Z^2, Y/Z^3).
static int ec_GFp_nistp384_point_get_affine_coordinates(
    const EC_GROUP *group, const EC_RAW_POINT *point, EC_FELEM *x_out,
    EC_FELEM *y_out) {
  if (ec_GFp_simple_is_at_infinity(group, point)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_AT_INFINITY);
    return 0;
  }

  fiat_p384_felem z1, z2;
  fiat_p384_from_generic(z1, &point->Z);
  fiat_p384_inv_square(z2, z1);

  if (x_out != NULL) {
    fiat_p384_felem x;
    fiat_p384_from_generic(x, &point->X);
    fiat_p384_mul(x, x, z2);
    fiat_p384_to_generic(x_out, x);
  }

  if (y_out != NULL) {
    fiat_p384_felem y;
    fiat_p384_from_generic(y, &point->Y);
    fiat_p384_square(z2, z2);  // z^-4
    fiat_p384_mul(y, y, z1);   // y * z
    fiat_p384_mul(y, y, z2);   // y * z^-3
    fiat_p384_to_generic(y_out, y);
  }

  return 1;
}

static void ec_GFp_nistp384_add(const EC_GROUP *group, EC_RAW_POINT *r,
                                const EC_RAW_POINT *a, const EC_RAW_POINT *b) {
  fiat_p384_felem x1, y1, z1, x2, y2, z2;
  fiat_p384_from_generic(x1, &a->X);
  fiat_p384_from_generic(y1, &a->Y);
  fiat_p384_from_generic(z1, &a->Z);
  fiat_p384_from_generic(x2, &b->X);
  fiat_p384_from_generic(y2, &b->Y);
  fiat_p384_from_generic(z2, &b->Z);
  fiat_p384_point_add(x1, y1, z1, x1, y1, z1, 0 /* both Jacobian */, x2, y2, z2);
  fiat_p384_to_generic(&r->X, x1);
  fiat_p384_to_generic(&r->Y, y1);
  fiat_p384_to_generic(&r->Z, z1);
}

static void ec_GFp_nistp384_dbl(const EC_GROUP *group, EC_RAW_POINT *r,
                                const EC_RAW_POINT *a) {
  fiat_p384_felem x, y, z;
  fiat_p384_from_generic(x, &a->X);
  fiat_p384_from_generic(y, &a->Y);
  fiat_p384_from_generic(z, &a->Z);
  fiat_p384_point_double(x, y, z, x, y, z);
  fiat_p384_to_generic(&r->X, x);
  fiat_p384_to_generic(&r->Y, y);
  fiat_p384_to_generic(&r->Z, z);
}

// The calls to from/to_generic are needed for the case
// when BORINGSSL_HAS_UINT128 is undefined, i.e. p384_32.h fiat code is used;
// while OPENSSL_64_BIT is defined, i.e. BN_ULONG is uint64_t
static void ec_GFp_nistp384_mont_felem_to_bytes(const EC_GROUP *group, uint8_t *out,
                                         size_t *out_len, const EC_FELEM *in) {
  size_t len = BN_num_bytes(&group->field);
  EC_FELEM felem_tmp;
  fiat_p384_felem tmp;
  fiat_p384_from_generic(tmp, in);
  fiat_p384_from_montgomery(tmp, tmp);
  fiat_p384_to_generic(&felem_tmp, tmp);

  // Convert to a big-endian byte array.
  for (size_t i = 0; i < len; i++) {
    out[i] = felem_tmp.bytes[len - 1 - i];
  }
  *out_len = len;
}

static int ec_GFp_nistp384_mont_felem_from_bytes(const EC_GROUP *group, EC_FELEM *out,
                                          const uint8_t *in, size_t len) {
  EC_FELEM felem_tmp;
  fiat_p384_felem tmp;
  // This function calls bn_cmp_words_consttime
  if (!ec_GFp_simple_felem_from_bytes(group, &felem_tmp, in, len)) {
    return 0;
  }
  fiat_p384_from_generic(tmp, &felem_tmp);
  fiat_p384_to_montgomery(tmp, tmp);
  fiat_p384_to_generic(out, tmp);
  return 1;
}

static int ec_GFp_nistp384_cmp_x_coordinate(const EC_GROUP *group,
                                            const EC_RAW_POINT *p,
                                            const EC_SCALAR *r) {
  if (ec_GFp_simple_is_at_infinity(group, p)) {
    return 0;
  }

  // We wish to compare X/Z^2 with r. This is equivalent to comparing X with
  // r*Z^2. Note that X and Z are represented in Montgomery form, while r is
  // not.
  fiat_p384_felem Z2_mont;
  fiat_p384_from_generic(Z2_mont, &p->Z);
  fiat_p384_mul(Z2_mont, Z2_mont, Z2_mont);

  fiat_p384_felem r_Z2;
  fiat_p384_from_bytes(r_Z2, r->bytes);  // r < order < p, so this is valid.
  fiat_p384_mul(r_Z2, r_Z2, Z2_mont);

  fiat_p384_felem X;
  fiat_p384_from_generic(X, &p->X);
  fiat_p384_from_montgomery(X, X);

  if (OPENSSL_memcmp(&r_Z2, &X, sizeof(r_Z2)) == 0) {
    return 1;
  }

  // During signing the x coefficient is reduced modulo the group order.
  // Therefore there is a small possibility, less than 2^189/2^384 = 1/2^195,
  // that group_order < p.x < p.
  // In that case, we need not only to compare against |r| but also to
  // compare against r+group_order.
  assert(group->field.width == group->order.width);
  if (bn_less_than_words(r->words, group->field_minus_order.words,
                         group->field.width)) {
    // We can ignore the carry because: r + group_order < p < 2^384.
    EC_FELEM tmp;
    bn_add_words(tmp.words, r->words, group->order.d, group->order.width);
    fiat_p384_from_generic(r_Z2, &tmp);
    fiat_p384_mul(r_Z2, r_Z2, Z2_mont);
    if (OPENSSL_memcmp(&r_Z2, &X, sizeof(r_Z2)) == 0) {
      return 1;
    }
  }

  return 0;
}

//                    SCALAR MULTIPLICATION OPERATIONS
// ----------------------------------------------------------------------------

// fiat_p384_get_bit returns the |i|-th bit in |in|
static crypto_word_t fiat_p384_get_bit(const uint8_t *in, int i) {
  if (i < 0 || i >= 384) {
    return 0;
  }
  return (in[i >> 3] >> (i & 7)) & 1;
}

// Constants for scalar encoding in the scalar multiplication functions.
#define FIAT_P384_SCALAR_RADIX       (5)
#define FIAT_P384_SCALAR_DRADIX      (1 << FIAT_P384_SCALAR_RADIX)
#define FIAT_P384_SCALAR_DRADIX_WNAF ((FIAT_P384_SCALAR_DRADIX) << 1)
#define FIAT_P384_MUL_TABLE_SIZE     ((FIAT_P384_SCALAR_DRADIX) >> 1)

// Compute "regular" wNAF representation of a scalar.
// See "Exponent Recoding and Regular Exponentiation Algorithms",
// Tunstall et al., AfricaCrypt 2009, Alg 6.
// It forces an odd scalar and outputs digits in
// {\pm 1, \pm 3, \pm 5, \pm 7, \pm 9, ...}
// i.e. signed odd digits with _no zeroes_ -- that makes it "regular".
static void fiat_p384_mul_scalar_rwnaf(int8_t *out, const unsigned char *in) {
  int8_t window, d;

  window = (in[0] & (FIAT_P384_SCALAR_DRADIX_WNAF - 1)) | 1;
  for (size_t i = 0; i < 76; i++) {
    d = (window & (FIAT_P384_SCALAR_DRADIX_WNAF - 1)) - FIAT_P384_SCALAR_DRADIX;
    out[i] = d;
    window = (window - d) >> FIAT_P384_SCALAR_RADIX;
    window += fiat_p384_get_bit(in, (i + 1) * FIAT_P384_SCALAR_RADIX + 1) << 1;
    window += fiat_p384_get_bit(in, (i + 1) * FIAT_P384_SCALAR_RADIX + 2) << 2;
    window += fiat_p384_get_bit(in, (i + 1) * FIAT_P384_SCALAR_RADIX + 3) << 3;
    window += fiat_p384_get_bit(in, (i + 1) * FIAT_P384_SCALAR_RADIX + 4) << 4;
    window += fiat_p384_get_bit(in, (i + 1) * FIAT_P384_SCALAR_RADIX + 5) << 5;
  }
  out[76] = window;
}

// Compute "textbook" wNAF representation of a scalar.
// It outputs digits in {0, \pm 1, \pm 3, \pm 5, \pm 7, \pm 9, ...}.
// A digits is either a zero or an odd integer. It is guaranteed that a non-zero
// digit is followed by at least (FIAT_P384_SCALAR_DRADIX - 1) zero digits.
//
// Note: this function is not constant-time.
static void fiat_p384_mul_scalar_wnaf(int8_t *out, const unsigned char *in) {
  int8_t window, d;

  window = in[0] & (FIAT_P384_SCALAR_DRADIX_WNAF - 1);
  for (size_t i = 0; i < 385; i++) {
    d = 0;
    if ((window & 1) && ((d = window & (FIAT_P384_SCALAR_DRADIX_WNAF - 1)) &
                         FIAT_P384_SCALAR_DRADIX)) {
      d -= FIAT_P384_SCALAR_DRADIX_WNAF;
    }

    out[i] = d;
    window = (window - d) >> 1;
    window += (fiat_p384_get_bit(in, i + 1 + FIAT_P384_SCALAR_RADIX)) <<
                                                                      FIAT_P384_SCALAR_RADIX;
  }
}

// fiat_p384_select_point selects the |idx|-th projective point from the given
// precomputed table and copies it to |out| in constant time.
static void fiat_p384_select_point(fiat_p384_felem out[3],
                                   size_t idx,
                                   fiat_p384_felem table[][3],
                                   size_t table_size) {
  OPENSSL_memset(out, 0, sizeof(fiat_p384_felem) * 3);
  for (size_t i = 0; i < table_size; i++) {
    fiat_p384_limb_t mismatch = i ^ idx;
    fiat_p384_cmovznz(out[0], mismatch, table[i][0], out[0]);
    fiat_p384_cmovznz(out[1], mismatch, table[i][1], out[1]);
    fiat_p384_cmovznz(out[2], mismatch, table[i][2], out[2]);
  }
}

// fiat_p384_select_point_affine selects the |idx|-th affine point from
// the given precomputed table and copies it to |out| in constant-time.
static void fiat_p384_select_point_affine(fiat_p384_felem out[2],
                                          size_t idx,
                                          const fiat_p384_felem table[][2],
                                          size_t table_size) {
  OPENSSL_memset(out, 0, sizeof(fiat_p384_felem) * 2);
  for (size_t i = 0; i < table_size; i++) {
    fiat_p384_limb_t mismatch = i ^ idx;
    fiat_p384_cmovznz(out[0], mismatch, table[i][0], out[0]);
    fiat_p384_cmovznz(out[1], mismatch, table[i][1], out[1]);
  }
}

// Multiplication of a point by a scalar, r = [scalar]P.
// The product is computed with the use of a small table generated on-the-fly
// and the scalar recoded in the regular-wNAF representation.
//
// The precomputed table |p_pre_comp| holds 16 odd multiples of P:
//     [2i + 1]P for i in [0, 15].
// Computing the negation of a point P = (x, y) is relatively easy -P = (x, -y).
// So we may assume that instead of the above mentioned 16, we have 32 points:
//     [\pm 1]P, [\pm 3]P, [\pm 5]P, ..., [\pm 31]P.
//
// The 384-bit scalar is recoded (regular-wNAF encoding) into 77 digits
// each of length 5 bits, as explained in the |fiat_p384_mul_scalar_rwnaf|
// function. Namely,
//     scalar' = s_0 + s_1*2^5 + s_2*2^10 + ... + s_76*2^380,
// where digits s_i are in [\pm 1, \pm 3, ..., \pm 31]. Note that for an odd
// scalar we have that scalar = scalar', while in the case of an even
// scalar we have that scalar = scalar' - 1.
//
// The required product, [scalar]P, is computed by the following algorithm.
//     1. Initialize the accumulator with the point from |p_pre_comp|
//        corresponding to the most significant digit s_76 of the scalar.
//     2. For digits s_i starting from s_75 down to s_0:
//     3.   Double the accumulator 5 times. (note that doubling a point [a]P
//          five times results in [2^5*a]P).
//     4.   Read from |p_pre_comp| the point corresponding to abs(s_i),
//          negate it if s_i is negative, and add it to the accumulator.
//
// Note: this function is constant-time.
static void ec_GFp_nistp384_point_mul(const EC_GROUP *group, EC_RAW_POINT *r,
                                      const EC_RAW_POINT *p,
                                      const EC_SCALAR *scalar) {

  fiat_p384_felem res[3], tmp[3], ftmp;

  // Table of multiples of P:  [2i + 1]P for i in [0, 15].
  fiat_p384_felem p_pre_comp[FIAT_P384_MUL_TABLE_SIZE][3];

  // Set the first point in the table to P.
  fiat_p384_from_generic(p_pre_comp[0][0], &p->X);
  fiat_p384_from_generic(p_pre_comp[0][1], &p->Y);
  fiat_p384_from_generic(p_pre_comp[0][2], &p->Z);

  // Compute tmp = [2]P.
  fiat_p384_point_double(tmp[0], tmp[1], tmp[2],
                         p_pre_comp[0][0], p_pre_comp[0][1], p_pre_comp[0][2]);

  // Generate the remaining 15 multiples of P.
  for (size_t i = 1; i < FIAT_P384_MUL_TABLE_SIZE; i++) {
    fiat_p384_point_add(p_pre_comp[i][0], p_pre_comp[i][1], p_pre_comp[i][2],
                        tmp[0], tmp[1], tmp[2], 0 /* mixed */,
                        p_pre_comp[i - 1][0], p_pre_comp[i - 1][1],
                        p_pre_comp[i - 1][2]);
  }

  // Recode the scalar.
  int8_t rnaf[77] = {0};
  fiat_p384_mul_scalar_rwnaf(rnaf, scalar->bytes);

  // Initialize the accumulator |res| with the table entry corresponding to
  // the most significant digit of the recoded scalar (note that this digit
  // can't be negative).
  int8_t idx = rnaf[76] >> 1;
  fiat_p384_select_point(res, idx, p_pre_comp, FIAT_P384_MUL_TABLE_SIZE);

  // Process the remaining digits of the scalar.
  for (size_t i = 75; i < 76; i--) {
    // Double |res| 5 times in each iteration.
    for (size_t j = 0; j < FIAT_P384_SCALAR_RADIX; j++) {
      fiat_p384_point_double(res[0], res[1], res[2], res[0], res[1], res[2]);
    }

    int8_t d = rnaf[i];
    // is_neg = (d < 0) ? 1 : 0
    int8_t is_neg = (d >> 7) & 1;
    // d = abs(d)
    d = (d ^ -is_neg) + is_neg;

    idx = d >> 1;

    // Select the point to add, in constant time.
    fiat_p384_select_point(tmp, idx, p_pre_comp, FIAT_P384_MUL_TABLE_SIZE);

    // Negate y coordinate of the point tmp = (x, y); ftmp = -y.
    fiat_p384_opp(ftmp, tmp[1]);
    // Conditionally select y or -y depending on the sign of the digit |d|.
    fiat_p384_cmovznz(tmp[1], is_neg, tmp[1], ftmp);

    // Add the point to the accumulator |res|.
    fiat_p384_point_add(res[0], res[1], res[2], res[0], res[1], res[2],
                        0 /* mixed */, tmp[0], tmp[1], tmp[2]);

  }

  // Conditionally subtract P if the scalar is even, in constant-time.
  // First, compute |tmp| = |res| + (-P).
  fiat_p384_copy(tmp[0], p_pre_comp[0][0]);
  fiat_p384_opp(tmp[1], p_pre_comp[0][1]);
  fiat_p384_copy(tmp[2], p_pre_comp[0][2]);
  fiat_p384_point_add(tmp[0], tmp[1], tmp[2], res[0], res[1], res[2],
                      0 /* mixed */, tmp[0], tmp[1], tmp[2]);

  // Select |res| or |tmp| based on the |scalar| parity, in constant-time.
  fiat_p384_cmovznz(res[0], scalar->bytes[0] & 1, tmp[0], res[0]);
  fiat_p384_cmovznz(res[1], scalar->bytes[0] & 1, tmp[1], res[1]);
  fiat_p384_cmovznz(res[2], scalar->bytes[0] & 1, tmp[2], res[2]);

  // Copy the result to the output.
  fiat_p384_to_generic(&r->X, res[0]);
  fiat_p384_to_generic(&r->Y, res[1]);
  fiat_p384_to_generic(&r->Z, res[2]);
}

// Include the precomputed table for the based point scalar multiplication.
#include "p384_table.h"

// Multiplication of the base point G of P-384 curve with the given scalar.
// The product is computed with the Comb method using the precomputed table
// |fiat_p384_g_pre_comp| from |p384_table.h| file and the regular-wNAF scalar
// encoding.
//
// The |fiat_p384_g_pre_comp| table has 20 sub-tables each holding 16 points:
//      0 :      [1]G,        [3]G,  ..,       [31]G
//      1 : [1*2^20]G,   [3*2^20]G, ...,  [31*2^20]G
//                         ...
//      i : [1*2^20i]G, [3*2^20i]G, ..., [31*2^20i]G
//                         ...
//     19 :   [2^380]G, [3*2^380]G, ..., [31*2^380]G.
// Computing the negation of a point P = (x, y) is relatively easy -P = (x, -y).
// So we may assume that for each sub-table we have 32 points instead of 16:
//     [\pm 1*2^20i]G, [\pm 3*2^20i]G, ..., [\pm 31*2^20i]G.
//
// The 384-bit |scalar| is recoded (regular-wNAF encoding) into 77 digits
// each of length 5 bits, as explained in the |fiat_p384_mul_scalar_rwnaf|
// function. Namely,
//     scalar' = s_0 + s_1*2^5 + s_2*2^10 + ... + s_76*2^380,
// where digits s_i are in [\pm 1, \pm 3, ..., \pm 31]. Note that for an odd
// scalar we have that scalar = scalar', while in the case of an even
// scalar we have that scalar = scalar' - 1.
//
// To compute the required product, [scalar]G, we may do the following.
// Group the recoded digits of the scalar in 4 groups:
//                                            |   corresponding multiples in
//                    digits                  |   the recoded representation
//     -------------------------------------------------------------------------
//     (0): {s_0, s_4,  s_8, ..., s_72, s_76} |  { 2^0, 2^20, ..., 2^360, 2^380}
//     (1): {s_1, s_5,  s_9, ..., s_73}       |  { 2^5, 2^25, ..., 2^365}
//     (2): {s_2, s_6, s_10, ..., s_74}       |  {2^10, 2^30, ..., 2^370}
//     (3): {s_3, s_7, s_11, ..., s_75}       |  {2^15, 2^35, ..., 2^375}
//
// The group (0) digits correspond precisely to the multiples of G that are
// held in the 20 precomputed sub-tables, so we may simply read the appropriate
// points from the sub-tables and sum them all up (negating if needed, i.e., if
// a digit s_i is negative, we read the point corresponding to the abs(s_i) and
// negate it before adding it to the sum).
// The remaining three groups (1), (2), and (3), correspond to the multiples
// of G from the sub-tables multiplied additionally by 2^5, 2^10, and 2^15,
// respectively. Therefore, for these groups we may read the appropriate points
// from the table, double them 5, 10, or 15 times, respectively, and add them
// to the final result.
//
// To minimize the number of required doublings we process the digits of the
// scalar from left to right. In other words, the algorithm is:
//   1. Read the points corresponding to the group (3) digits from the table
//      and add them to an accumulator.
//   2. Double the accumulator 5 times.
//   3. Repeat steps 1. and 2. for groups (2) and (1),
//      and perform step 1. for group (0).
//   4. If the scalar is even subtract G from the accumulator.
//
// Note: this function is constant-time.
static void ec_GFp_nistp384_point_mul_base(const EC_GROUP *group,
                                           EC_RAW_POINT *r,
                                           const EC_SCALAR *scalar) {

  fiat_p384_felem res[3] = {{0}, {0}, {0}}, tmp[3] = {{0}, {0}, {0}}, ftmp;
  int8_t rnaf[77] = {0};

  // Recode the scalar.
  fiat_p384_mul_scalar_rwnaf(rnaf, scalar->bytes);

  // Process the 4 groups of digits starting from group (3) down to group (0).
  for (size_t i = 3; i < 4; i--) {
    // Double |res| 5 times in each iteration except the first one.
    for (size_t j = 0; i != 3 && j < FIAT_P384_SCALAR_RADIX; j++) {
      fiat_p384_point_double(res[0], res[1], res[2], res[0], res[1], res[2]);
    }

    // For each digit |d| in the current group read the corresponding point from
    // the table and add it to |res|. If |d| is negative negate the read point
    // before adding to |res|.
    for (size_t j = i; j < 77; j += 4) {
      int8_t d = rnaf[j];
      // is_neg = (d < 0) ? 1 : 0
      int8_t is_neg = (d >> 7) & 1;
      // d = abs(d)
      d = (d ^ -is_neg) + is_neg;

      int8_t idx = d >> 1;

      // Select the point to add, in constant time.
      fiat_p384_select_point_affine(tmp, idx, fiat_p384_g_pre_comp[j / 4], 16);

      // Negate y coordinate of the point tmp = (x, y); ftmp = -y.
      fiat_p384_opp(ftmp, tmp[1]);
      // Conditionally select y or -y depending on the sign of the digit |d|.
      fiat_p384_cmovznz(tmp[1], is_neg, tmp[1], ftmp);

      // Add the point to the accumulator |res|.
      // Note that the points in the pre-computed table are given with affine
      // coordinates. The point addition function computes a sum of two points,
      // either both given in projective, or one in projective and the other one
      // in affine coordinates. The |mixed| flag indicates the latter option,
      // in which case we set the third coordinate of the second point to one.
      fiat_p384_point_add(res[0], res[1], res[2], res[0], res[1], res[2],
                          1 /* mixed */, tmp[0], tmp[1], fiat_p384_one);
    }
  }

  // Conditionally subtract G if the scalar is even, in constant-time.
  // First, compute |tmp| = |res| + (-G).
  fiat_p384_copy(tmp[0], fiat_p384_g_pre_comp[0][0][0]);
  fiat_p384_opp(tmp[1], fiat_p384_g_pre_comp[0][0][1]);
  fiat_p384_point_add(tmp[0], tmp[1], tmp[2], res[0], res[1], res[2],
                      1 /* mixed */, tmp[0], tmp[1], fiat_p384_one);

  // Select |res| or |tmp| based on the |scalar| parity.
  fiat_p384_cmovznz(res[0], scalar->bytes[0] & 1, tmp[0], res[0]);
  fiat_p384_cmovznz(res[1], scalar->bytes[0] & 1, tmp[1], res[1]);
  fiat_p384_cmovznz(res[2], scalar->bytes[0] & 1, tmp[2], res[2]);

  // Copy the result to the output.
  fiat_p384_to_generic(&r->X, res[0]);
  fiat_p384_to_generic(&r->Y, res[1]);
  fiat_p384_to_generic(&r->Z, res[2]);
}

// Computes [g_scalar]G + [p_scalar]P, where G is the base point of the P-384
// curve, and P is the given point |p|.
//
// Both scalar products are computed by the same "textbook" wNAF method.
// For the base point G product we use the first sub-table of the precomputed
// table |fiat_p384_g_pre_comp| from p384_table.h file, while for P we generate
// the |p_pre_comp| table on-the-fly. The tables hold the first 15 odd multiples
// of G or P:
//     g_pre_comp = {[1]G, [3]G, ..., [31]G},
//     p_pre_comp = {[1]P, [3]P, ..., [31]P}.
// Computing the negation of a point P = (x, y) is relatively easy -P = (x, -y).
// So we may assume that we also have the negatives of the points in the tables.
//
// The 384-bit scalars are recoded by the textbook wNAF method to 385 digits,
// where a digit is either a zero or an odd integer in [-31, 31]. The method
// guarantees that each non-zero digit is followed by at least four
// zeroes.
//
// The result [g_scalar]G + [p_scalar]P is computed by the following algorithm:
//     1. Initialize the accumulator with the point-at-infinity.
//     2. For i starting from 384 down to 0:
//     3.   Double the accumulator (doubling can be skipped while the
//          accumulator is equal to the point-at-infinity).
//     4.   Read from |p_pre_comp| the point corresponding to the i-th digit of
//          p_scalar, negate it if the digit is negative, and add it to the
//          accumulator.
//     5.   Read from |g_pre_comp| the point corresponding to the i-th digit of
//          g_scalar, negate it if the digit is negative, and add it to the
//          accumulator.
//
// Note: this function is NOT constant-time.
static void ec_GFp_nistp384_point_mul_public(const EC_GROUP *group,
                                             EC_RAW_POINT *r,
                                             const EC_SCALAR *g_scalar,
                                             const EC_RAW_POINT *p,
                                             const EC_SCALAR *p_scalar) {

  fiat_p384_felem res[3] = {{0}, {0}, {0}}, tmp[3], ftmp;

  // Table of multiples of P:  [2i + 1]P for i in [0, 15].
  fiat_p384_felem p_pre_comp[FIAT_P384_MUL_TABLE_SIZE][3];

  // Set the first point in the table to P.
  fiat_p384_from_generic(p_pre_comp[0][0], &p->X);
  fiat_p384_from_generic(p_pre_comp[0][1], &p->Y);
  fiat_p384_from_generic(p_pre_comp[0][2], &p->Z);

  // Compute tmp = [2]P.
  fiat_p384_point_double(tmp[0], tmp[1], tmp[2],
                         p_pre_comp[0][0], p_pre_comp[0][1], p_pre_comp[0][2]);

  // Generate the remaining 15 multiples of P.
  for (size_t i = 1; i < FIAT_P384_MUL_TABLE_SIZE; i++) {
    fiat_p384_point_add(p_pre_comp[i][0], p_pre_comp[i][1], p_pre_comp[i][2],
                        tmp[0], tmp[1], tmp[2], 0 /* mixed */,
                        p_pre_comp[i - 1][0], p_pre_comp[i - 1][1],
                        p_pre_comp[i - 1][2]);
  }

  // Recode the scalars.
  int8_t p_wnaf[385] = {0}, g_wnaf[385] = {0};
  fiat_p384_mul_scalar_wnaf(p_wnaf, p_scalar->bytes);
  fiat_p384_mul_scalar_wnaf(g_wnaf, g_scalar->bytes);

  // In the beginning res is set to point-at-infinity so we set the flag.
  int8_t res_is_inf = 1;
  int8_t d, is_neg, idx;

  for (size_t i = 384; i < 385; i--) {

    // If |res| is point-at-infinity there is not point in doubling so skip it.
    if (!res_is_inf) {
      fiat_p384_point_double(res[0], res[1], res[2], res[0], res[1], res[2]);
    }

    // Process the p_scalar digit.
    d = p_wnaf[i];
    if (d != 0) {
      is_neg = d < 0 ? 1 : 0;
      idx = (is_neg) ? (-d - 1) >> 1 : (d - 1) >> 1;

      if (res_is_inf) {
        // If |res| is point-at-infinity there is not to add the new point,
        // we can simply copy it.
        fiat_p384_copy(res[0], p_pre_comp[idx][0]);
        fiat_p384_copy(res[1], p_pre_comp[idx][1]);
        fiat_p384_copy(res[2], p_pre_comp[idx][2]);
        res_is_inf = 0;
      } else {
        // Otherwise add to the accumulator either the point at position idx
        // in the table or its negation.
        if (is_neg) {
          fiat_p384_opp(ftmp, p_pre_comp[idx][1]);
        } else {
          fiat_p384_copy(ftmp, p_pre_comp[idx][1]);
        }
        fiat_p384_point_add(res[0], res[1], res[2],
                            res[0], res[1], res[2],
                            0 /* mixed */,
                            p_pre_comp[idx][0], ftmp, p_pre_comp[idx][2]);
      }
    }

    // Process the g_scalar digit.
    d = g_wnaf[i];
    if (d != 0) {
      is_neg = d < 0 ? 1 : 0;
      idx = (is_neg) ? (-d - 1) >> 1 : (d - 1) >> 1;

      if (res_is_inf) {
        // If |res| is point-at-infinity there is not to add the new point,
        // we can simply copy it.
        fiat_p384_copy(res[0], fiat_p384_g_pre_comp[0][idx][0]);
        fiat_p384_copy(res[1], fiat_p384_g_pre_comp[0][idx][1]);
        fiat_p384_copy(res[2], fiat_p384_one);
        res_is_inf = 0;
      } else {
        // Otherwise add to the accumulator either the point at position idx
        // in the table or its negation.
        if (is_neg) {
          fiat_p384_opp(ftmp, fiat_p384_g_pre_comp[0][idx][1]);
        } else {
          fiat_p384_copy(ftmp, fiat_p384_g_pre_comp[0][idx][1]);
        }
        // Add the point to the accumulator |res|.
        // Note that the points in the pre-computed table are given with affine
        // coordinates. The point addition function computes a sum of two points,
        // either both given in projective, or one in projective and the other one
        // in affine coordinates. The |mixed| flag indicates the latter option,
        // in which case we set the third coordinate of the second point to one.
        fiat_p384_point_add(res[0], res[1], res[2],
                            res[0], res[1], res[2],
                            1 /* mixed */,
                            fiat_p384_g_pre_comp[0][idx][0], ftmp, fiat_p384_one);
      }
    }
  }

  // Copy the result to the output.
  fiat_p384_to_generic(&r->X, res[0]);
  fiat_p384_to_generic(&r->Y, res[1]);
  fiat_p384_to_generic(&r->Z, res[2]);
}

DEFINE_METHOD_FUNCTION(EC_METHOD, EC_GFp_nistp384_method) {
  out->group_init = ec_GFp_mont_group_init;
  out->group_finish = ec_GFp_mont_group_finish;
  out->group_set_curve = ec_GFp_mont_group_set_curve;
  out->point_get_affine_coordinates =
      ec_GFp_nistp384_point_get_affine_coordinates;
  out->jacobian_to_affine_batch =
      ec_GFp_mont_jacobian_to_affine_batch;     // needed for TrustToken tests
  out->add = ec_GFp_nistp384_add;
  out->dbl = ec_GFp_nistp384_dbl;
  out->mul = ec_GFp_nistp384_point_mul;
  out->mul_base = ec_GFp_nistp384_point_mul_base;
  out->mul_public = ec_GFp_nistp384_point_mul_public;
  out->mul_batch = ec_GFp_mont_mul_batch;       // needed for TrustToken tests
  out->mul_public_batch = ec_GFp_mont_mul_public_batch;
  out->init_precomp = ec_GFp_mont_init_precomp; // needed for TrustToken tests
  out->mul_precomp = ec_GFp_mont_mul_precomp;   // needed for TrustToken tests
  out->felem_mul = ec_GFp_mont_felem_mul;
  out->felem_sqr = ec_GFp_mont_felem_sqr;
  out->felem_to_bytes = ec_GFp_nistp384_mont_felem_to_bytes;
  out->felem_from_bytes = ec_GFp_nistp384_mont_felem_from_bytes;
  out->felem_reduce = ec_GFp_mont_felem_reduce; // needed for ECTest.HashToCurve
  out->felem_exp = ec_GFp_mont_felem_exp;       // needed for ECTest.HashToCurve
  out->scalar_inv0_montgomery = ec_simple_scalar_inv0_montgomery;
  out->scalar_to_montgomery_inv_vartime =
      ec_simple_scalar_to_montgomery_inv_vartime;
  out->cmp_x_coordinate = ec_GFp_nistp384_cmp_x_coordinate;
}
