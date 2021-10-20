# Setup of Intel SGX and Gramine-SGX

This setup document is for installing Intel SGX and Gramine together on Linux machines with Intel CPUs. The provided script doesn't support all Linux distributions or kernel versions, however the steps described below should be generic enough for all Linux distributions.

The setup script provided will detect the Linux distribution and kernel version, and it only supports Ubuntu 20.04 and CentOS 8. It sets up the SGX and Gramine by the steps below automatically (except for the BIOS setting).

## BIOS setup for SGX

### Ice Lake SP Xeon platform

Please follow page 4 of this [Setup doc](https://download.01.org/intelsgxstack/2021-04-30/Getting_Started.pdf) to setup memory and BIOS. The BIOS settings are copied below.

Ensure the following BIOS settings are set as shown:

- TME enable:

```
Advanced -> Socket Configuration -> Processor Configuration -> TME, MK-TME, TDX -> Total Memory Encryption -> Enable
```

NOTE: SGX will be visible only if TME is enabled.

- Disable UMA-Based Clustering (Otherwise SGX will be grayed out):

```
Advanced -> Socket Configuration -> Common RefCode Configuration -> UMA-Based Clustering -> Disable
```

- Enable SGX:

```
Advanced -> Socket Configuration -> Processor Configuration -> SW Guard Extensions(SGX) -> Enable
```

- Disable Patrol scrub (Only LCC & HCC):

```
Advanced -> Socket Configuration -> Memory RAS Configuration -> Patrol Scrub -> Disable
```

- Disable Mirroring:

```
Advanced -> Socket Configuration -> Memory RAS Configuration -> Mirror Mode -> Disable
```

- Enable Memory ECC

### Desktop platforms

On desktop/laptop platforms the BIOS setup is simpler, normally only one option for enabling SGX and another for SGX reserved memory size. Setting SGX to enabled should be enough.

## Install Intel SGX driver

There are three SGX drivers available:
- the SGX driver built in mainline kernel since v5.11
- the SGX DCAP driver [source code](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- the legacy out-of-tree driver [source code](https://github.com/intel/linux-sgx-driver)

The SGX driver is upstreamed in mainline kernel since v5.11, so if the target kernel is already 5.11+, no other SGX driver is needed. If `/dev/sgx_enclave` and `/dev/sgx_provision` don't exist, please check the kernel config `CONFIG_X86_SGX` to make sure the SGX driver is enabled.

If the kernel version is below v5.11, the SGX DCAP driver is recommended and should be used for platforms w/ FLC (Flexible Launch Control). Unless the platform doesn't support or configured FLC, the legacy out-of-tree SGX driver could be used.

For Gramine, it requires the kernel has FSGSBASE enabled, kernels equal or above v5.9 has it enabled by default, otherwise please update kernel or apply FSGSBASE patch.

## Install Intel SGX SDK and PSW

After SGX BIOS setting and SGX driver are ready, [SGX SDK and PSW](https://github.com/intel/linux-sgx) is needed.

The SDK and PSW could be installed from source or using pre-built binaries for Intel 01.org:
- [Binaries from 01.org](https://01.org/intel-software-guard-extensions/downloads), preferred
- [Build from source](https://github.com/intel/linux-sgx)

Please follow the document of each SGX release of 01.org to install prebuilt binaries, for example, v2.14 release [Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.14/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf). the provided script uses prebuilt v2.14 release, w/o part of PSW installation that is irrelevant to the usages.

## Install Gramine-SGX

With SGX BIOS settings, driver, SDK and PSW ready, Gramine could be compiled and installed. Follow the official doc [Building](https://gramine.readthedocs.io/en/latest/building.html) to compile and install gramine with SGX PAL. The SGX dependency section could be skipped since it's already set up in above sections of this document.

However the Gramine official document only has latest version so the users checking the [Building](https://gramine.readthedocs.io/en/latest/building.html) URL may find the steps may have changed. The provided script uses [gramine v1.2-rc1](https://github.com/gramineproject/gramine/tree/v1.2-rc1), and the steps are from time near v1.2-rc1 release date.

## Verify SGX and Gramine-SGX

In gramine source there's a tool `is_sgx_available` in `Pal/src/host/Linux-SGX/tools/is-sgx-available` to report all SGX settings, also Gramine has a `helloworld` test to verify basic readiness. Please check the script.
