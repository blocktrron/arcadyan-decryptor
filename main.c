/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/* Stage 1 */
#define S1_OUTER_HEADER_OFFSET 0x200
#define S1_OUTER_HEADER_IV_OFFSET 0x200
#define S1_OUTER_HEADER_DATA_OFFSET 0x220
#define S1_OUTER_HEADER_LEN 0x280
#define S1_DEC_HEADER_INSTALLER_IV_OFFSET 0x10
#define S1_DEC_HEADER_INSTALLER_KEY_OFFSET 0x20
#define S1_DEC_HEADER_IMAGE_IV_OFFSET 0x40
#define S1_DEC_HEADER_IMAGE_KEY_OFFSET 0x50
#define S1_IMG_INSTALLER_OFFSET 0x4a0

/* Stage 2 */
#define S2_SZ_SIZE 0x10
#define S2_SZ_IV_OFFSET 0x00
#define S2_SZ_DATA_OFFSET 0x20

#define S2_ENC_HDR_IV_OFFSET 0x10
#define S2_ENC_HDR_DATA_OFFSET 0x30

#define S2_DEC_HDR_NUM_FILES_OFFSET 0x40
#define S2_DEC_HDR_SIGNING_TYPE_OFFSET 0x41
#define S2_DEC_HDR_ENC_TYPE_OFFSET 0x44
#define S2_DEC_HDR_FILE_META_TABLE_BASE_OFFSET 0x68

#define S2_FILE_META_TABLE_SIZE 0x78
#define S2_FILE_META_TABLE_NAME_OFFSET 0x00
#define S2_FILE_META_TABLE_SIZE_OFFSET 0x40
#define S2_FILE_META_TABLE_IV_OFFSET 0x48
#define S2_FILE_META_TABLE_KEY_OFFSET 0x58

const uint8_t arcadyan_key[] = {
        0xa5, 0x24, 0xc9, 0x94, 0x33, 0x34, 0x80, 0xb1,
        0xdf, 0x4a, 0x01, 0x64, 0xde, 0x7f, 0x29, 0xa5,
        0xe9, 0x4d, 0x99, 0xe4, 0xd2, 0x4e, 0x72, 0xf3,
        0xce, 0x58, 0xa8, 0xe6, 0xe4, 0xb1, 0xf6, 0xde
};

const uint8_t arcadyan_stage2_size_key[] = {
        0x2e, 0x34, 0x19, 0xed, 0x09, 0x78, 0x36, 0x51,
        0x20, 0xf3, 0xd5, 0x71, 0x3c, 0x83, 0x89, 0x27,
        0x36, 0x47, 0x4f, 0x43, 0x92, 0x54, 0xc7, 0x3d,
        0x36, 0x6c, 0x39, 0x55, 0x38, 0x6c, 0xfe, 0x91
};

const uint8_t arcadyan_stage2_header_key[] = {
        0xab, 0x08, 0xb1, 0x3c, 0x44, 0xf6, 0x1a, 0x4d,
        0xc9, 0xef, 0xb5, 0xb4, 0x81, 0x1a, 0x1c, 0x74,
        0xda, 0xdd, 0x15, 0x7d, 0xbd, 0x2d, 0x09, 0x75,
        0xf8, 0x36, 0x1e, 0xf7, 0x7b, 0xd1, 0x22, 0x5e
};

struct arc_file {
    /* File path */
    char *path;
    size_t filesize;

    /* File data */
    uint8_t *buf;
    size_t buf_size;
};

struct arc_decrypt {
    struct arc_file *public_key_file;
    struct arc_file *input_file;
    struct arc_file *installer_file;
    struct arc_file *image_file;

    const char *input_filename;
    const char *output_path;
};

static const char *arc_get_filename(const char *path) {
    const char *filename = strrchr(path, '/');
    if (filename == NULL) {
        return path;
    }

    return filename + 1;
}

static char *arc_get_output_filename(struct arc_decrypt *arc, const char *filename) {
    char *output_filename;
    size_t output_len;

    output_len = strlen(arc->output_path) + 1 + strlen(arc->input_filename) + 1 + strlen(filename) + 1;
    output_filename = calloc(1, output_len);
    if (output_filename == NULL) {
        fprintf(stderr, "Error: Could not allocate memory\n");
        return NULL;
    }

    snprintf(output_filename, output_len, "%s/%s.%s", arc->output_path, arc->input_filename, filename);

    return output_filename;
}

static struct arc_file *arc_file_init(const char *path) {
    struct arc_file *file = malloc(sizeof(struct arc_file));
    if (file == NULL) {
        return NULL;
    }

    file->path = strdup(path);
    file->filesize = 0;
    file->buf = NULL;
    file->buf_size = 0;

    return file;
}

static void arc_file_free(struct arc_file *file) {
    if (file->buf != NULL) {
        free(file->buf);
    }

    if (file->path != NULL) {
        free(file->path);
    }

    free(file);
}

static int arc_file_read(struct arc_file *file) {
    FILE *fp = fopen(file->path, "r");
    if (fp == NULL) {
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    file->filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    file->buf = malloc(file->filesize);
    if (file->buf == NULL) {
        fclose(fp);
        return 1;
    }

    file->buf_size = file->filesize;

    fread(file->buf, 1, file->filesize, fp);
    fclose(fp);

    return 0;
}

static int arc_file_write(struct arc_file *file) {
    size_t written;
    FILE *fp;

    fp = fopen(file->path, "w");
    if (fp == NULL) {
        return 1;
    }

    written = fwrite(file->buf, 1, file->buf_size, fp);
    fclose(fp);

    if (written != file->buf_size) {
        fprintf(stderr, "Error: Could not write to file\n");
        return 1;
    }

    file->filesize = file->buf_size;

    return 0;
}

int arc_fw_sha512(uint8_t *data, size_t data_len, uint8_t *hash) {
    SHA512_CTX sha_ctx;

    if (SHA512_Init(&sha_ctx) == 0) {
        fprintf(stderr, "Error: Could not initialize SHA-512 context\n");
        return 1;
    }

    if (SHA512_Update(&sha_ctx, data, data_len) == 0) {
        fprintf(stderr, "Error: Could not update SHA-512 context\n");
        return 1;
    }

    if (SHA512_Final(hash, &sha_ctx) == 0) {
        fprintf(stderr, "Error: Could not finalize SHA-512 context\n");
        return 1;
    }

    return 0;
}


static int arc_fw_decrypt_hash(struct arc_decrypt *arc, uint8_t *input, int len, uint8_t *output) {
    BIO *pubkey_bio = NULL;
    RSA *rsa = NULL;
    int ret = 0;

    /* Read RSA pubkey from pubkey buffer */
    pubkey_bio = BIO_new_mem_buf(arc->public_key_file->buf, arc->public_key_file->filesize);
    if (pubkey_bio == NULL) {
        fprintf(stderr, "Error: Could not create BIO from public key buffer\n");
        ret = 1;
        goto out_free;
    }

    PEM_read_bio_RSA_PUBKEY(pubkey_bio, &rsa, NULL, NULL);
    if (rsa == NULL) {
        fprintf(stderr, "Error: Could not read RSA public key\n");
        return 1;
    }

    /* Decrypt first 0x200 bytes of the input file */
    if (RSA_public_decrypt(len, input, output, rsa, RSA_PKCS1_PADDING) == -1) {
        fprintf(stderr, "Error: Could not decrypt RSA encrypted hash\n");
        ret = 1;
        goto out_free;
    }

out_free:
    if (pubkey_bio != NULL) {
        BIO_free(pubkey_bio);
    }
    if (rsa != NULL) {
        RSA_free(rsa);
    }
    return ret;
}

static int arc_fw_verify_hmac(struct arc_decrypt *arc, uint8_t *data, int data_len, uint8_t *rsa_compare) {
    uint8_t hash[SHA512_DIGEST_LENGTH];
    uint8_t decrypted_hash[0x200];

    /* Decrypt comparison value */
    if (arc_fw_decrypt_hash(arc, rsa_compare, 0x200, decrypted_hash) != 0) {
        return 1;
    }

    if (arc_fw_sha512(data, data_len, hash) != 0) {
        return 1;
    }

    if (memcmp(hash, decrypted_hash, SHA512_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "Error: Hashes do not match\n");
        return 1;
    }

    return 0;
}


static uint8_t *arc_fw_aes256(const uint8_t *key, uint8_t *iv, uint8_t *buf, uint32_t *buf_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    uint8_t *tmp_buf;
    int tmp_buf_len;
    int final_buf_len;
    int ret = 0;

    tmp_buf_len = *buf_len;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: Could not create cipher context\n");
        ret = 1;
    }

    cipher = EVP_aes_256_cbc();
    if (cipher == NULL) {
        fprintf(stderr, "Error: Could not create AES cipher\n");
        ret = 1;
        goto out_free;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == 0) {
        fprintf(stderr, "Error: Could not initialize AES decryption\n");
        ret = 1;
        goto out_free;
    }

    tmp_buf = malloc(*buf_len + 0x10);
    final_buf_len = 0;
    if (EVP_DecryptUpdate(ctx, tmp_buf, &tmp_buf_len, buf, *buf_len) == 0) {
        fprintf(stderr, "Error: Could not decrypt input buffer\n");
        ret = 1;
        goto out_free;
    }

    if (EVP_DecryptFinal_ex(ctx, tmp_buf + tmp_buf_len, &final_buf_len) == 0) {
        fprintf(stderr, "Error: Could not finalize AES decryption\n");
        ret = 1;
        goto out_free;
    }

    *buf_len = final_buf_len + tmp_buf_len;

out_free:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    if (cipher != NULL) {
        //EVP_CIPHER_free(cipher);
    }

    if (ret != 0) {
        fprintf(stderr, "Error: AES decryption failed\n");
        free(tmp_buf);
        return NULL;
    }
    return tmp_buf;
}

uint32_t arc_byteswap(uint8_t *data, size_t num_pairs) {
    uint32_t *header;

    header = (uint32_t *)data;

    /**
     * header[0] = ntohl(header[1]);
     * header[1] = ntohl(header[0]);
     * header[2] = ntohl(header[3]);
     * header[3] = ntohl(header[2]);
     * ...
     */

    uint32_t h0, h1;
    for (int i = 0; i < num_pairs; i++) {
        h0 = header[(i*2) + 0];
        h1 = header[(i*2) + 1];
        header[(i*2) + 0] = ntohl(h1);
        header[(i*2) + 1] = ntohl(h0);
    }

    return 0;
}

uint32_t arc_magic_stage1(uint8_t *header_ptr, uint32_t *installer_size, uint32_t *image_size) {
    uint32_t *header;

    arc_byteswap(header_ptr, 2);

    header = (uint32_t *)header_ptr;
    *installer_size = (header[0] & ~0xf) + 0x10;
    *image_size = (header[2] & ~0xf) + 0x10;

    return *installer_size + *image_size;
}

uint32_t arcadyan_magic_stage2(uint8_t *header) {
    arc_byteswap(header, 1);
    return (*((uint32_t *)header) & 0xfffffff0) + 0x10;
}

int arc_fw_decrypt_stage1(struct arc_decrypt *arc) {
    uint8_t *decrypted_header, *decrypted_installer, *decrypted_image;
    uint32_t header_size, installer_size, installer_enc_size, image_size, inner_header_size;
    int ret;

    ret = 0;
    decrypted_header = NULL;
    decrypted_installer = NULL;
    decrypted_image = NULL;

    /* Check if the input file is bigger than 0x200 */
    if (arc->input_file->filesize < 0x200) {
        fprintf(stderr, "Error: Input file is too small\n");
        return 1;
    }

    /* Validate outer header */
    fprintf(stdout, "Validate outer header\n");
    if (arc_fw_verify_hmac(arc, arc->input_file->buf + S1_OUTER_HEADER_OFFSET, arc->input_file->filesize - S1_OUTER_HEADER_OFFSET, arc->input_file->buf) != 0) {
        fprintf(stderr, "Error: Could not verify outer header\n");
        return 1;
    }

    /* Decrypt header */
    fprintf(stdout, "Decrypt outer header\n");
    header_size = S1_OUTER_HEADER_LEN;
    decrypted_header = arc_fw_aes256(arcadyan_key, arc->input_file->buf + S1_OUTER_HEADER_IV_OFFSET,
                                     arc->input_file->buf + S1_OUTER_HEADER_DATA_OFFSET, &header_size);
    if (!decrypted_header) {
        fprintf(stderr, "Error: Could not decrypt header\n");
        ret = 1;
        goto out_free;
    }

    /* Validate inner header */
    fprintf(stdout, "Validate Installer and Image\n");
    inner_header_size = arc_magic_stage1(decrypted_header, &installer_size, &image_size);
    installer_enc_size = installer_size;
    if (arc_fw_verify_hmac(arc, arc->input_file->buf + S1_IMG_INSTALLER_OFFSET, inner_header_size, decrypted_header + 0x70) != 0) {
        fprintf(stderr, "Error: Could not verify inner header\n");
        ret = 1;
        goto out_free;
    }

    /* Decrypt installer */
    fprintf(stdout, "Decrypt installer size=0x%x\n", installer_size);
    decrypted_installer = arc_fw_aes256(decrypted_header + S1_DEC_HEADER_INSTALLER_KEY_OFFSET,
                                        decrypted_header + S1_DEC_HEADER_INSTALLER_IV_OFFSET,
                                        arc->input_file->buf + S1_IMG_INSTALLER_OFFSET, &installer_size);
    if (!decrypted_installer) {
        fprintf(stderr, "Error: Could not decrypt installer\n");
        ret = 1;
        goto out_free;
    }

    /* Write installer to file */
    arc->installer_file->buf = decrypted_installer;
    arc->installer_file->buf_size = installer_size;
    arc_file_write(arc->installer_file);

    /* Decrypt image */
    fprintf(stdout, "Decrypt image size=0x%x\n", image_size);
    decrypted_image = arc_fw_aes256(decrypted_header + S1_DEC_HEADER_IMAGE_KEY_OFFSET,
                                    decrypted_header + S1_DEC_HEADER_IMAGE_IV_OFFSET,
                                    arc->input_file->buf + S1_IMG_INSTALLER_OFFSET + installer_enc_size, &image_size);
    if (!decrypted_image) {
        fprintf(stderr, "Error: Could not decrypt image\n");
        ret = 1;
        goto out_free;
    }

    /* Write image to file */
    arc->image_file->buf = decrypted_image;
    arc->image_file->buf_size = image_size;
    arc_file_write(arc->image_file);

out_free:
    return ret;
}

int arc_fw_stage2_save_file(struct arc_decrypt *arc, uint8_t *filename, uint8_t *data, uint32_t data_len) {
    struct arc_file *file = NULL;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_len;
    uint8_t *full_path;
    int ret;

    ret = 0;

    full_path = arc_get_output_filename(arc, filename);
    if (!full_path) {
        fprintf(stderr, "Error: Could not get full path\n");
        ret = 1;
        return 1;
    }

    file = arc_file_init(full_path);
    if (file == NULL) {
        fprintf(stderr, "Error: Could not allocate memory\n");
        ret = 1;
        goto out_free;
    }

    file->buf = data;
    file->buf_size = data_len;
    arc_file_write(file);

out_free:
    if (file)
        arc_file_free(file);
    if (full_path)
        free(full_path);

    return ret;
}

int arc_fw_decrypt_stage2(struct arc_decrypt *arc) {
    uint32_t header_size_decrypted, header_size_encrypted;
    uint32_t hash_size, hash_size_tmp;
    uint8_t *decrypted_size_header, *decrypted_header;
    uint32_t num_files, hash_length, data_len;
    uint8_t *hash_ptr, *data_ptr, *file_meta_table, *file_meta_table_base;
    uint8_t fw_encryption_type, fw_signing_type;
    uint8_t *decrypted_file;
    uint32_t decrypted_file_len;
    uint32_t i;
    int ret;

    ret = 0;
    decrypted_size_header = NULL;
    decrypted_header = NULL;

    /* Decrypt header */
    header_size_encrypted = S2_SZ_SIZE;
    header_size_decrypted = header_size_encrypted;
    decrypted_size_header = arc_fw_aes256(arcadyan_stage2_size_key, arc->image_file->buf + S2_SZ_IV_OFFSET,
                                          arc->image_file->buf + S2_SZ_DATA_OFFSET, &header_size_decrypted);
    if (!decrypted_size_header) {
        fprintf(stderr, "Error: Could not decrypt header\n");
        ret = 1;
        goto out_free;
    }
    hash_size = arcadyan_magic_stage2(decrypted_size_header);
    fprintf(stdout, "Size-header decrypted=0x%x encrypted=0x%x hash_size=0x%x\n", header_size_decrypted, header_size_encrypted, hash_size);

    hash_size_tmp = hash_size;
    decrypted_header = arc_fw_aes256(arcadyan_stage2_header_key, arc->image_file->buf + S2_ENC_HDR_IV_OFFSET,
                                     arc->image_file->buf + S2_SZ_DATA_OFFSET + S2_SZ_SIZE, &hash_size_tmp);
    if (!decrypted_header) {
        fprintf(stderr, "Error:arc_ma Could not decrypt header\n");
        ret = 1;
        goto out_free;
    }

    switch (decrypted_header[S2_DEC_HDR_SIGNING_TYPE_OFFSET]) {
        case 0:
            hash_length = 0x40;
            break;
        case 1:
            hash_length = 0x200;
            break;
        default:
            fprintf(stderr, "Error: Unsupported hash length\n");
            ret = 1;
            goto out_free;
    }

    num_files = (uint32_t)decrypted_header[S2_DEC_HDR_NUM_FILES_OFFSET];
    fw_signing_type = decrypted_header[S2_DEC_HDR_SIGNING_TYPE_OFFSET];
    fw_encryption_type = decrypted_header[S2_DEC_HDR_ENC_TYPE_OFFSET];
    file_meta_table_base = &decrypted_header[S2_DEC_HDR_FILE_META_TABLE_BASE_OFFSET];

    hash_ptr = arc->image_file->buf + S2_ENC_HDR_DATA_OFFSET + hash_size;
    for (i = 0; i < num_files; i++) {
        decrypted_file = NULL;
        data_ptr = hash_ptr + hash_length;
        file_meta_table = &file_meta_table_base[i * S2_FILE_META_TABLE_SIZE];

        /* Fix endianess */
        arc_byteswap(&file_meta_table[S2_FILE_META_TABLE_SIZE_OFFSET], 1);
        data_len = *(uint32_t *)(&file_meta_table[S2_FILE_META_TABLE_SIZE_OFFSET]);
        fprintf(stdout, "Process idx=%u file=%s size=%x\n", i, &file_meta_table[S2_FILE_META_TABLE_NAME_OFFSET], data_len);

        /* Fix data length depending on encryption type */
        switch (fw_encryption_type) {
            case 0:
                /* No encryption */
                break;
            case 1:
                /* AES256-CBC */
                data_len = (data_len & 0xfffffff0) + 0x10;
                break;
            default:
                fprintf(stderr, "Unsupported encryption type\n");
                ret = 1;
                goto out_free;
        }

        /* Verify Checksum */
        if (fw_signing_type == 1) {
            /* Verify HMAC */
            if (arc_fw_verify_hmac(arc, data_ptr, data_len, hash_ptr)) {
                fprintf(stderr, "Error: Could not verify HMAC\n");
                ret = 1;
                goto out_free;
            }
        } else if (fw_signing_type == 0) {
            fprintf(stdout, "Checksum is not encrypted. Compare SHA512\n");
            /* ToDo: Implement */
        }

        /* Decrypt if necessary*/
        if (fw_encryption_type == 0) {
            /* No encryption */
            decrypted_file_len = 0;
            decrypted_file = NULL;
        }
        else if (fw_encryption_type == 1) {
            /* AES256-CBC */
            decrypted_file_len = data_len;
            decrypted_file = arc_fw_aes256(&file_meta_table[S2_FILE_META_TABLE_KEY_OFFSET], &file_meta_table[S2_FILE_META_TABLE_IV_OFFSET], data_ptr,
                                           &decrypted_file_len);
            if (!decrypted_file) {
                fprintf(stderr, "Error: Could not decrypt data\n");
                ret = 1;
                goto out_free;
            }
        }

        /* Save file to output folder */
        if (arc_fw_stage2_save_file(arc, file_meta_table, decrypted_file, decrypted_file_len)) {
            fprintf(stderr, "Error: Could not save file\n");
            ret = 1;
            goto out_free;
        }

        hash_ptr = data_ptr + data_len;
    }

out_free:
    free(decrypted_size_header);
    free(decrypted_header);
    if (ret)
        free(decrypted_file);

    return ret;
}


int main(int argc, char *argv[]) {
    struct arc_decrypt *arc = NULL;
    char *output_filename;
    int ret = 0;

    if (argc < 4) {
        printf("Usage: %s <public_key_file> <input_file> <output-path>\n", argv[0]);
        ret = 1;
        goto out_free;
    }

    arc = calloc(1, sizeof(struct arc_decrypt));
    if (arc == NULL) {
        fprintf(stderr, "Error: Could not allocate memory\n");
        ret = 1;
        goto out_free;
    }

    arc->input_filename = arc_get_filename(argv[2]);
    arc->output_path = argv[3];

    arc->public_key_file = arc_file_init(argv[1]);
    arc->input_file = arc_file_init(argv[2]);

    output_filename = arc_get_output_filename(arc, "s1_installer");
    arc->installer_file = arc_file_init(arc_get_output_filename(arc, output_filename));
    free(output_filename);

    output_filename = arc_get_output_filename(arc, "s1_image");
    arc->image_file = arc_file_init(output_filename);
    free(output_filename);

    if (arc->public_key_file == NULL || arc->input_file == NULL || arc->installer_file == NULL || arc->image_file == NULL) {
        ret = 1;
        goto out_free;
    }

    if (arc_file_read(arc->public_key_file) != 0) {
        fprintf(stderr, "Error: Could not read public key file\n");
        ret = 1;
        goto out_free;
    }

    if (arc_file_read(arc->input_file) != 0) {
        fprintf(stderr, "Error: Could not read input file\n");
        ret = 1;
        goto out_free;
    }

    fprintf(stdout, "-- Stage 1 --\n");
    if (arc_fw_decrypt_stage1(arc)) {
        fprintf(stderr, "Error: Could not decrypt stage 1\n");
        ret = 1;
        goto out_free;
    }

    fprintf(stdout, "-- Stage 2 --\n");
    if (arc_fw_decrypt_stage2(arc)) {
        fprintf(stderr, "Error: Could not decrypt stage 2\n");
        ret = 1;
        goto out_free;
    }

out_free:
    if (!arc) {
        return 1;
    }

    if (arc->public_key_file != NULL) {
        arc_file_free(arc->public_key_file);
    }
    if (arc->input_file != NULL) {
        arc_file_free(arc->input_file);
    }
    if (arc->installer_file != NULL) {
        arc_file_free(arc->installer_file);
    }
    if (arc->image_file != NULL) {
        arc_file_free(arc->image_file);
    }

    free(arc);

    return ret;
}
