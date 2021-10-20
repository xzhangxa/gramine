#!/bin/bash

set -e

SGX_01ORG_2_14_UBUNTU_PATH=https://download.01.org/intel-sgx/sgx-linux/2.14/distro/ubuntu20.04-server
SGX_DCAP_DRIVER_UBUNTU=${SGX_01ORG_2_14_UBUNTU_PATH}/sgx_linux_x64_driver_1.41.bin
SGX_SDK_UBUNTU=${SGX_01ORG_2_14_UBUNTU_PATH}/sgx_linux_x64_sdk_2.14.100.2.bin

SGX_DCAP_DRIVER_URL=""
SGX_DCAP_DRIVER=""
SGX_SDK_URL=""
SGX_SDK=""
SGX_PSW_URL=""
SGX_PSW=""

INSTALL_SGX_DRIVER=0

OS=""
VER=""
WORKING_DIR=`pwd`
SETUP_PATH=$WORKING_DIR/gramine_sgx_files

echoerr() {
    echo "$@" 1>&2
    exit 1
}

distribution_check() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    fi

    if [[ "$OS" =~ Ubuntu ]]; then
        SGX_DCAP_DRIVER_URL=$SGX_DCAP_DRIVER_UBUNTU
        SGX_SDK_URL=$SGX_SDK_UBUNTU
        if [[ ! "$VER" =~ 20.04 ]]; then
            echoerr "Found Ubuntu but it's not 20.04, exiting..."
        fi
    else
        echoerr "Distribution is not Ubuntu, exiting..."
    fi
    SGX_DCAP_DRIVER=`basename $SGX_DCAP_DRIVER_URL`
    SGX_SDK=`basename $SGX_SDK_URL`
    echo "Found OS is $OS $VER"
}

install_gramine_dependencies() {
    sudo apt update
    sudo apt-get install -y autoconf bison build-essential gawk \
        python3 python3-click python3-jinja2 wget \
        python3-pip python3-toml git openssl
    pip3 install --user meson
}

install_gramine() {
    cd $SETUP_PATH
    git clone https://github.com/gramineproject/gramine.git --branch=v1.0
    cd gramine
    openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072
    if [[ $INSTALL_SGX_DRIVER -eq 1 ]]; then
        meson setup build/ --buildtype=release -Ddirect=disabled -Dsgx=enabled
            -Dsgx_driver="dcap1.10" -Dsgx_driver_include_path="/usr/src/sgx-1.41/include/"
    else
        meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled -Dsgx_driver=upstream
    fi
    ninja -C build/
    PYTHONPATH=~/.local/lib/python3.8/site-packages sudo -E ninja -C build/ install
}

verify_gramine() {
    cd $SETUP_PATH/gramine/Pal/src/host/Linux-SGX/tools/is-sgx-available
    is_sgx_available

    cd $SETUP_PATH/gramine/LibOS/shim/test/regression
    make SGX=1
    make SGX=1 sgx-tokens
    gramine-sgx helloworld
}

install_dcap_driver_dependencies() {
    sudo apt update
    sudo apt-get install -y build-essential ocaml automake autoconf libtool wget libssl-dev dkms
}

install_sgx_dependencies() {
    sudo apt update
    sudo apt-get install -y build-essential wget \
        libcurl4-openssl-dev libprotobuf-c-dev \
        protobuf-c-compiler python3-protobuf
}

download_sgx() {
    cd $SETUP_PATH
    if [[ $INSTALL_SGX_DRIVER -eq 1 ]]; then
        wget $SGX_DCAP_DRIVER_URL -O $SGX_DCAP_DRIVER
        chmod 777 $SGX_DCAP_DRIVER
    fi

    wget $SGX_SDK_URL -O $SGX_SDK
    chmod 777 $SGX_SDK

    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add
    sudo apt-get update
}

install_sgx() {
    cd $SETUP_PATH
    # Install SGX DCAP Driver
    if [[ $INSTALL_SGX_DRIVER -eq 1 ]]; then
        install_dcap_driver_dependencies
        sudo ./$SGX_DCAP_DRIVER
    fi

    # Install SGX PSW
    cd $SETUP_PATH
    sudo apt-get install -y libsgx-epid libsgx-quote-ex libsgx-dcap-ql

    # Install SGX SDK
    cd $SETUP_PATH
    sudo ./$SGX_SDK <<EOF
no
/opt/intel
EOF
    sudo apt-get install -y libsgx-enclave-common-dev libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev
}

kernel_version_check() {
    KERVER=`uname --kernel-release`
    KERVER_MAJOR=`echo $KERVER | cut -d '.' -f 1 -`
    KERVER_MINOR=`echo $KERVER | cut -d '.' -f 2 -`

    if [[ $KERVER_MAJOR -lt 5 || $KERVER_MINOR -lt 9 ]]
    then
        echoerr "Kernel version must be 5.9+ to have FSGSBASE enabled, please update kernel or apply FSGSBASE patch. Exiting..."
    fi

    if [[ $KERVER_MINOR -lt 11 ]]
    then
        echo "Kernel version is lower than 5.11, SGX driver needs to be installed manually."
        INSTALL_SGX_DRIVER=1
    fi
}

help() {
    echo "$0: setup machine for SGX and gramine"
    echo "    - This script only support Ubuntu 20.04"
    echo "    - SGX SDK and PSW will be installed from official 2.14 binary releases"
    echo "    - SGX DCAP Driver will be installed if kernel in [5.9 - 5.11)"
    echo "    - Older kernels w/o FSGSBASE won't be supported, please update kernel or apply FSGSBASE patch"
    echo "    - gramine will be built/installed from source to /usr/local, only SGX PAL is enabled"
}

main() {
    if [ -d $SETUP_PATH ]; then
        rm -rf $SETUP_PATH
    fi
    mkdir -p $SETUP_PATH

    echo "********************************"
    echo "****** Distribution Check ******"
    distribution_check
    echo "**********************************"
    echo "****** Kernel Version Check ******"
    kernel_version_check
    echo "***********************************************"
    echo "****** Install SGX Software Dependencies ******"
    install_sgx_dependencies

    echo "*****************************************"
    echo "****** Download SGX Software Stack ******"
    download_sgx
    echo "****************************************"
    echo "****** Install SGX Software Stack ******"
    install_sgx

    echo "*******************************************"
    echo "****** Install gramine Dependencies ******"
    install_gramine_dependencies
    echo "******************************"
    echo "****** Install gramine ******"
    install_gramine
    echo "*****************************"
    echo "****** Verify gramine ******"
    verify_gramine
}

i=1;
for arg in "$@"
do
    if [ "$arg" == "-h" ] || [ "$arg" == "--help" ]; then
        help
        exit
    else
        echoerr "Unknown argument $arg"
    fi
    i=$((i + 1));
done

main
