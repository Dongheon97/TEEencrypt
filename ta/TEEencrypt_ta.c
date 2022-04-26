/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int root_key;
int random_key;

// Start RSA functions
struct rsa_session{
	TEE_OperationHandle op_handle; 	// RSA Operation
	TEE_ObjectHandle key_handle;	// key handle
};

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg,
					TEE_OperationMode mode, TEE_ObjectHandle key){
	TEE_Result ret = TEE_SUCCESS;
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);

	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);

	DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types){
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
							TEE_PARAM_TYPE_MEMREF_OUTPUT,
							TEE_PARAM_TYPE_NONE,
							TEE_PARAM_TYPE_NONE);
	// Safely get the invocation paramters
	if(param_types != exp_param_types){
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *sess_ctx){
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)sess_ctx;
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);

	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);

	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *sess_ctx, uint32_t param_types, TEE_Param params[4]){
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)sess_ctx;

	if(check_params(param_types) != TEE_SUCCESS){
		DMSG("\n\nBAD_PARAMETERS\n\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);

	DMSG("\nData to encrypt: %s\n", (char*) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0, plain_txt,
					plain_len, cipher, &cipher_len);

	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully =========\n");
	return ret;

	err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}
// End RSA function

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */

// Modified for RSA Encryption Session
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types, TEE_Param __unused params[4], void __unused **sess_ctx){
        struct rsa_session *sess;
        sess = TEE_Malloc(sizeof(*sess), 0);
        if(!sess) return TEE_ERROR_OUT_OF_MEMORY;
        sess->key_handle = TEE_HANDLE_NULL;
        sess->op_handle = TEE_HANDLE_NULL;
        *sess_ctx = (void *)sess;
        DMSG("\nSession %p: newly allocated\n", *sess_ctx);
        IMSG("\n\nHELLO WORLD!\n\n");
        return TEE_SUCCESS;
}
void TA_CloseSessionEntryPoint(void *sess_ctx){
        DMSG("\nEnter close session\n");
	struct rsa_session *sess;
        //DMSG("Session %p: release session", sess_ctx);
        DMSG("\nStruct\n");
	sess = (struct rsa_session *)sess_ctx;
	DMSG("\nsess\n");
	TEE_Free(sess);
        DMSG("FREE OK");
	IMSG("\n\nGOOD BYE\n\n");
}

static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	char encrypted[64] = {0,};

	DMSG("========================Encryption========================\n");
	DMSG("Plaintext: %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len; i++){
		if(encrypted[i] >= 'a' && encrypted[i] <= 'z'){
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if(encrypted[i] >= 'A' && encrypted[i] <= 'Z'){
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	DMSG("Ciphertext: %s", encrypted);
	memcpy(in, encrypted, in_len);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4])
{
        char * in = (char *)params[0].memref.buffer;
        int in_len = strlen(params[0].memref.buffer);
        char decrypted[64] = {0,};

        DMSG("========================Decryption========================\n");
        DMSG ("Ciphertext:  %s", in);
        memcpy(decrypted, in, in_len);

        for(int i=0; i<in_len-1;i++){
                if(decrypted[i]>='a' && decrypted[i] <='z'){
                        decrypted[i] -= 'a';
                        decrypted[i] -= random_key;
                        decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
                        decrypted[i] += 'a';
                }
                else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
                        decrypted[i] -= 'A';
                        decrypted[i] -= random_key;
			decrypted[i] += 26;
                        decrypted[i] = decrypted[i] % 26;
                        decrypted[i] += 'A';
                }
        }
	decrypted[in_len-1] = '\0';	// NULL
        DMSG ("Plaintext:  %s", decrypted);
        memcpy(in, decrypted, in_len);

        return TEE_SUCCESS;
}

static TEE_Result randomkey_get(uint32_t param_types, TEE_Param params[4])
{
        DMSG("========================Get RandomKey========================\n");
        // 1 <= Random Key <= 25
        do{
                TEE_GenerateRandom(&random_key, sizeof(random_key));
                random_key = random_key % 26;
        }while(random_key == 0);
	if(random_key < 0){
		random_key *= -1;
	}
        DMSG("Random Key: %d\n", random_key);
        return TEE_SUCCESS;
}

static TEE_Result randomkey_enc(uint32_t param_types, TEE_Param params[4])
{
	DMSG("========================RandomKey Encryption========================\n");

	if(random_key >= 'a' && random_key <= 'z'){
		random_key -= 'a';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'a';
	}
	else if(random_key >= 'A' && random_key <= 'Z'){
		random_key -= 'A';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'A';
	}
	params[1].value.a = (uint32_t)random_key;
	return TEE_SUCCESS;
}

static TEE_Result randomkey_dec(uint32_t param_types, TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	char encrypted[64] = {0,};

	DMSG("========================RandomKey Decryption========================\n");
	memcpy(encrypted, in, in_len);

	// Get Random Key
	random_key = encrypted[in_len-1];
	DMSG("Random Key: %d\n", random_key);

	if(random_key >= 'a' && random_key <= 'z'){
		random_key -= 'a';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'a';
	}
	else if(random_key >= 'A' && random_key <= 'Z'){
		random_key -= 'A';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'A';
	}
	DMSG("Got Value: %c\n", encrypted[in_len-1]);
	DMSG("Decrypted: %d\n", random_key);
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	root_key = 3;

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return randomkey_get(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return randomkey_enc(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
		return randomkey_dec(param_types, params);
	case TA_TEEencrypt_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_TEEencrypt_RSA_CMD_ENCRYPT:
		return RSA_encrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
