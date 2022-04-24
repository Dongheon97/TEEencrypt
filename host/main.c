#include <err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

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


	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	//op.params[0].tmpref.buffer = plaintext;
	//op.params[0].tmpref.size = len;

	// Encryption
	if(strcmp(argv[1], "-e")==0){
		// Parameters init
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;

		// Read file
		//FILE* fpr = fopen(argv[2], "r");
		//fread(plaintext, sizeof(plaintext), 1, fpr);
		//fclose(fpr);

		fpr = open(argv[2], O_RDONLY);
		read(fd, plaintext, len);
		close(fpr);

		// Encrypt
		printf("========================Encryption========================\n");
		printf("plaintext: %s\n", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GET_RANDOMKEY, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RANDOMKEY, &op, &err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("ciphertext: %s\n", ciphertext);
		encrypted_key[0] = op.params[0].value.a;
		encrypted_key[1] = '\0';		// NULL
		strcat(ciphertext, encrypted_key);	// Concat String

		// Write file
		//FILE* fpw = fopen("./ciphertext.txt", "w");
		//fwrite(ciphertext, strlen(ciphertext), 1, fpw);
		//fclose(fpw);
		fdw = creat("./ciphertext.txt", 0644);
		write(fdw, ciphertext, strlen(ciphertext));
		close(fdw);
	}
	else if(strcmp(argv[1], "-d")==0){
		// Parameters init
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;

		// Read file
		FILE* fpr = fopen(argv[2], "r");
		fgets(ciphertext, sizeof(ciphertext), fpr);
		fclose(fpr);

		// Decrypt
		printf("========================Encryption========================\n");
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_RANDOMKEY, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext: %s\n", plaintext);

		FILE* fpw = fopen("./plaintext.txt", "w");
		fputs(plaintext, fpw);
		fclose(fpw);
	}

	//res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
	//res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
	//res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
	//res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
