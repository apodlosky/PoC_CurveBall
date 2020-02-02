# CVE-2020-0601 - CurveBall

## Highlights

 - PoC for CVE-2020-0601
 - Trivial solution for private-key of 1
 - Non-trivial solution for 1 < private-key < curve-order
 - Written in C, uses OpenSSL's libcrypto

## Requirements

 - Linux of some variety
 - ``apt install libssl libssl-dev``
   - Or whatever package mananger you use

## Compiling

 - ``make``

## Usage

 - ./curveball MicrosoftECCProductRootCA2018.cer

 - ./curveball -d 555 MicrosoftECCProductRootCA2018.cer
