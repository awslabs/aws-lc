#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source tests/ci/common_posix_setup.sh

echo "Testing AWS-LC in FIPS debug mode."
fips_build_and_test

echo "Testing AWS-LC in FIPS release mode."
fips_build_and_test -DCMAKE_BUILD_TYPE=Release

if [[  "${AWSLC_NO_ASM_FIPS}" == "1" ]]; then
  # This dimension corresponds to boringssl CI 'linux_fips_noasm_asan'.
  # https://logs.chromium.org/logs/boringssl/buildbucket/cr-buildbucket.appspot.com/8852496158370398336/+/steps/cmake/0/logs/execution_details/0
  echo "Testing AWS-LC in FIPS OPENSSL_NO_ASM release mode."
  fips_build_and_test -DASAN=1 -DOPENSSL_NO_ASM=1 -DCMAKE_BUILD_TYPE=Release
fi
