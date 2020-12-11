
BENCH_DIR=$PWD
AWSLC_DIR=$BENCH_DIR/../aws-lc
OPENSSL_DIR=$BENCH_DIR/../openssl
PROJECT=benchmark_ec_p256
OPENSSL102=0

# Process input parameters and append them to the options string
options=''
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -t|--test)
            options+=" -t $2";
            shift ;;
        -i|--iterations)
            options+=" -i $2";
            shift ;;
        --ossl102)
            OPENSSL102=1;
            OPENSSL102_DIR=$BENCH_DIR/../openssl102/openssl;;
        --cpu_ticks)
            CPU_TICKS=1;;
        *)
            echo "Unknown parameter passed: $1" && \
            echo "Possible options are: " && \
            echo " benchmark-build-run.sh [-t|--test <\"ecdhp256\"|\"ecdsap256\">]" && \
            echo "                        [-i|--iterations <iterations>]" && \
            echo "                        [--ossl102]" && \
            echo "                        [--cpu_ticks]";
            exit 1 ;;
    esac
    shift
done

# Check that AWS-LC directory exists
if [[ ! -d $AWSLC_DIR ]]
then
    echo "$AWS-LC directory not found"; exit 1;
## checkout AWS-LC if it doesn't exist already
#     echo "Checkout AWS-LC main tip" && \
#         cd .. && \
#         git clone https://github.com/awslabs/aws-lc.git && \
#         cd $BENCH_DIR
fi

# build AWS-LC
echo "Build AWS-LC" && \
    cd $AWSLC_DIR && \
    mkdir -p build && \
    cd build && \
    cmake -DOPENSSL_AARCH64_P256=1 -DCMAKE_BUILD_TYPE=Release -GNinja .. && \
    ninja && \
    cd $BENCH_DIR

# checkout OpenSSL if it doesn't exist already
if [[ ! -d $OPENSSL_DIR ]]
then
    echo "Checkout tag OpenSSL_1_1_1h from OpenSSL" && \
        cd .. && \
        git clone --branch OpenSSL_1_1_1h --single-branch https://github.com/openssl/openssl.git && \
        cd $BENCH_DIR
fi

# build OpenSSL if libcrypto.a doesn't exist
[[ ! -f $OPENSSL_DIR/libcrypto.a ]] && \
    echo "Build OpenSSL" && \
    cd $OPENSSL_DIR && \
    ./config && \
    make && \
    cd $BENCH_DIR

# checkout OpenSSL 1.0.2 if specified
if [[ "$OPENSSL102" -eq 1 ]]
then
    if [[ ! -d $OPENSSL102_DIR ]]
    then
        echo "Checkout tag OpenSSL_1_0_2s from OpenSSL" && \
            cd .. && \
            mkdir -p openssl102 && \
            cd openssl102 && \
            git clone --branch OpenSSL_1_0_2s --single-branch https://github.com/openssl/openssl.git && \
            cd $BENCH_DIR
    fi
    # build OpenSSL 1.0.2 if libcrypto.a doesn't exist
    if [[ ! -f $OPENSSL102_DIR/libcrypto.a ]]
    then
        echo "Build OpenSSL 1.0.2" && \
            cd $OPENSSL102_DIR

        if [[ "$OSTYPE" == "darwin"* ]]
        then
            ./Configure darwin64-x86_64-cc && \
                make
        else
            ./config && \
                make
        fi
        cd $BENCH_DIR
    fi
fi


# build benchmark binaries
echo "Build benchmark binaries" && \
    mkdir -p build && \
    cd build && \
    cmake -DOPENSSL102_LIB="$OPENSSL102" -DCPU_TICKS="$CPU_TICKS" .. && \
    cmake --build .
# run benchmarks
echo
echo "Run P-256 AWS-LC benchmarks"
./${PROJECT}_awslc $options

echo
echo "Run P-256 OPENSSL benchmarks"
if [[ "$OSTYPE" == "darwin"* ]]
then
    DYLD_LIBRARY_PATH=${OPENSSL_DIR} ./${PROJECT}_ossl $options
else
    LD_LIBRARY_PATH=${OPENSSL_DIR} ./${PROJECT}_ossl $options
fi

if [[ "$OPENSSL102" -eq 1 ]]
then
    echo
    echo "Run P-256 OPENSSL 1.0.2 benchmarks"
    if [[ "$OSTYPE" == "darwin"* ]]
    then
        DYLD_LIBRARY_PATH=${OPENSSL102_DIR} ./${PROJECT}_ossl102 $options
    else
        LD_LIBRARY_PATH=${OPENSSL102_DIR} ./${PROJECT}_ossl102 $options
    fi
fi
