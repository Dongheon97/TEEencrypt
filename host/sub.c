#include <err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

/* Start RSA Functions */
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

/*
struct ta_attrs{
	TEEC_Context ctx;
	TEEC_Session sess;
};
*/
void rsa_gen_keys(int *sess){
	TEEC_Result res;
	res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_RSA_GENKEYS, NULL, NULL);
	if(res!=TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_RSA_GENKEYS) failed %#x\n", res);
	printf("\n========== Keys generated. =========\n");
}
/* End RSA Functions */

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encrypted_key[3];
	int len=64;

	//struct ta_attrs ta;
        char clear[RSA_MAX_PLAIN_LEN_1024];
        char ciph[RSA_CIPHER_LEN_1024];

	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	// Didn't Input Encryption Algorithm
	if(argc != 4){
		printf("Error: Please check your command\n");
	}
	else if(strcmp(argv[3], "Ceasar")==0){
		printf("\nCeasar Algorithm\n");
		// Encryption
        	if(strcmp(argv[1], "-e")==0){
                	// Parameters Init
                	//res = TEEC_InitializeContext(NULL, &ctx);
		        //res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		        //memset(&op, 0, sizeof(op));

			//op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
             		op.params[0].tmpref.buffer = plaintext;
                	op.params[0].tmpref.size = len;

                	// Read file
                	FILE* fpr = fopen(argv[2], "r");
                	fread(plaintext, sizeof(plaintext), 1, fpr);
                	fclose(fpr);

	                printf("========================Ceasar Encryption========================\n");
	                printf("Plaintext: %s\n", plaintext);

	                // Get Plaintext
	                memcpy(op.params[0].tmpref.buffer, plaintext, len);

	                // Encryption
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);

	                memcpy(ciphertext, op.params[0].tmpref.buffer, len);

			printf("Ciphertext: %s", ciphertext);
			printf("=================================================================\n");

			// Save ciphertext & encrypted random key to file
			encrypted_key[0] = op.params[1].value.a;
	                encrypted_key[1] = '\0';                // NULL
	                strcat(ciphertext, encrypted_key);      // Concat String

	                // Write file
	                FILE* fpw = fopen("./ciphertext.txt", "w");
	                fwrite(ciphertext, strlen(ciphertext), 1, fpw);
	                fclose(fpw);
	        }
		// Decryption
	        else if(strcmp(argv[1], "-d")==0){
	                // Parameters Init
	                //res = TEEC_InitializeContext(NULL, &ctx);
		        //res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		        //memset(&op, 0, sizeof(op));

			//op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	                op.params[0].tmpref.buffer = ciphertext;
	                op.params[0].tmpref.size = len;

	                // Read file
	                FILE* fpr = fopen(argv[2], "r");
	                fread(ciphertext, sizeof(ciphertext), 1, fpr);
	                fclose(fpr);

	                // Get Ciphertext
	                memcpy(op.params[0].tmpref.buffer, ciphertext, len);

	                printf("========================Ceasar Decryption========================\n");
			printf("Ciphertext: %s\n", ciphertext);

	                // Decryption
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

	                memcpy(plaintext, op.params[0].tmpref.buffer, len);
	                printf("Plaintext: %s", plaintext);

	                FILE* fpw = fopen("./plaintext.txt", "w");
	                fwrite(plaintext, strlen(plaintext), 1, fpw);
	                fclose(fpw);
	                printf("=================================================================\n");
	        }
	}
	// RSA Encryption
	else if(strcmp(argv[3], "RSA")==0){
		printf("\nRSA Algorithm\n");
		//struct ta_attrs ta;
		//char clear[RSA_MAX_PLAIN_LEN_1024];
		//char ciph[RSA_CIPHER_LEN_1024];
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		op.params[2].tmpref.buffer = clear;
		op.params[2].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
		op.params[3].tmpref.size = ciph;
		op.params[3].tmpref.size = RSA_CIPHER_LEN_1024;

		//prepare_ta_session(&ta);

		// Read file
                FILE* fpr = fopen(argv[2], "r");
                fread(plaintext, sizeof(RSA_MAX_PLAIN_LEN_1024), 1, fpr);
                fclose(fpr);

		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		printf("read file\n");

		// Encryption
		printf("==========================RSA Eecryption=========================\n");
		rsa_gen_keys(&sess);
		printf("rsa_gen_keys");

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENCRYPT, &op, &err_origin);
		//rsa_encrypt(&ta, plaintext, RSA_MAX_PLAIN_LEN_1024, ciphertext, RSA_CIPHER_LEN_1024);
		printf("=================================================================\n");

		// Write file
                FILE* fpw = fopen("./ciphertext.txt", "w");
                fwrite(ciphertext, strlen(RSA_CIPHER_LEN_1024), 1, fpw);
                fclose(fpw);

		//terminate_tee_session(sess);
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
