#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <list> 
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#define BUFFSIZE 1024
#define AES_BLOCK_SIZE 256

/**
 *  CS426 projec3
 *  Luzhe Wang    login:wang1106
 *	Si Yu         login:si1
 *
 */
using namespace std;

class mapa{
	public:
		char a0[20];
		string filename;
		char d0[BUFFSIZE];
		int num_entry;
		mapa( char * a0 , string filename , char * d ){
			for( int i = 0 ; i < 20 ; i++ )
				this->a0[i] = a0[i];
			this->filename = filename;
			this->num_entry = -1;
			for( int i = 0 ; i < BUFFSIZE ; i++ )
				d0[i] = d[i];
		}
		int set_num_entry( int num_entry ){
			this->num_entry = num_entry;
			return this->num_entry;
		}
};

list<mapa> mapalist;
FILE * current_file = NULL;
string current_filename;
int current_index;
char w[4];
char a[20];


/*
 * create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 *  **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
		EVP_CIPHER_CTX *d_ctx)
{
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/*
	 *    * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 *    * nrounds is the number of times the we hash the material. More rounds are more secure but
	 *    * slower.
	 *    */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		printf("Key size is %d bits - should be 256 bits\n", i);
		return -1;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 0;
}

/*
 *  * Encrypt *len bytes of data
 *  * All data going in & out is considered binary (unsigned char[])
 *  */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = (unsigned char *)malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *     *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

/*
 *  * Decrypt *len bytes of ciphertext
 *   */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

int char2int( char c ){
	switch(c){
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a': return 10;
		case 'b': return 11;
		case 'c': return 12;
		case 'd': return 13;
		case 'e': return 14;
		case 'f': return 15;
		defaule: return -1;
	}
	return -1;
}
bool ishex( char c ){
	switch(c){
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			return true;
		default:
			return false;
	}
	return false;
}
int fprintfHex( char * w , char * e , char * y , char *z ){
	if(current_file == NULL){
		return -1;
	}
	for( int i = 0 ; i < 4 ; i++ ){
		fprintf(current_file,"%02x",(unsigned char)w[i]);
	}
	for( int i = 0 ; i < 20 ; i++ ){
		fprintf(current_file,"%02x",(unsigned char)y[i]);
	}
	for( int i = 0 ; i < 20 ; i++ ){
		fprintf(current_file,"%02x",(unsigned char )z[i]);
	}
	for( int i = 0 ; i < BUFFSIZE ; i++ ){
		fprintf(current_file,"%02x",(unsigned char)e[i]);
	}
	fprintf(current_file,"\n");
	fflush(current_file);
	return 0;
}

int freadHex( string filename , int index , char * w , char * e , char * y , char * z ){
	FILE * f = fopen(filename.c_str(),"r");

	if( f == NULL ){
		return -1;
	}
	fseek(f,index*(2*(4+20+20+BUFFSIZE)+1),SEEK_SET);
	char c;
	for( int i = 0 ; i < 4 ; i++ ){
		w[i] = char2int(getc(f)) * 16;
		w[i] += char2int(getc(f));
	}
	
	for( int i = 0 ; i < 20 ; i++ ){
		y[i] = char2int(getc(f)) * 16;
		y[i] += char2int(getc(f));
	}
	for( int i = 0 ; i < 20 ; i++ ){
		z[i] = char2int(getc(f)) * 16;
		z[i] += char2int(getc(f));
	}
	for( int i = 0 ; i < BUFFSIZE ; i++ ){
		e[i] = char2int(getc(f)) * 16;
		e[i] += char2int(getc(f));
	}
	/*
	if( getc(f) != 0 ){
		fclose(f);
		return -2;
	}
	*/
	if( getc(f) != '\n' ){
		fclose(f);
		return -3;
	}
	fclose(f);
	return 0;
}
void savelogs(){
	FILE * of = fopen("mapalist_reserved","w");
	for( list<mapa>::iterator it = mapalist.begin() ; it != mapalist.end() ; it++ ){
		for( int i = 0 ; i < 20 ; i++ ){
			fprintf(of,"%02x",(unsigned char)it->a0[i]);
		}
		for( int i = 0 ; i < BUFFSIZE ; i++ ){
			fprintf(of,"%02x",(unsigned char)it->d0[i]);
		}
		fprintf(of,"%d ",it->num_entry);
		fprintf(of,"%s\n",it->filename.c_str());
	}
	fclose(of);
}
void init(){
	ifstream ifs("mapalist_reserved");
	string line;
	char c;
	while(getline(ifs,line)){
		istringstream iss(line);
		char tempa0[20];
		char tempd0[BUFFSIZE];
		int temp_num;
		string file_name;
		char c;
		int index = 0;
		for( int i = 0 ; i < 20 ; i++ ){
			iss >> c;
			tempa0[i] = char2int(c) * 16;
			iss >> c;
			tempa0[i] += char2int(c);
		}
		for( int i = 0 ; i < BUFFSIZE ; i++ ){
			iss >> c;
			tempd0[i] = char2int(c) * 16;
			iss >> c;
			tempd0[i] += char2int(c);
		}
		iss >> temp_num;
		iss >> file_name;
		mapa newm(tempa0,file_name,tempd0);
		newm.set_num_entry(temp_num);
		mapalist.push_back(newm);
	}
	/*
	for( list<mapa>::iterator it = mapalist.begin() ; it != mapalist.end() ; it++ ){
		cout << it->filename << endl;
		cout << it->num_entry << endl;
	}
	*/
	ifs.close();
}
void createlog( char * filename ){

	int current_timestamp = (int)time(NULL);
	int future_timestamp  = current_timestamp + 3600;
	
	for( list<mapa>::iterator it = mapalist.begin() ; it != mapalist.end() ; it++ ){
		if( it->filename.compare(filename) == 0 ){
			//cout << "file already exist" << endl;
			return;
		}
	}
	current_file = fopen(filename,"wr");
	if( current_file == NULL ){
		//cout << "Failed to create log" << endl;
		return;
	}
	current_filename = string(filename);
	char d[BUFFSIZE];
	sprintf(d,"%d,%d,%s",current_timestamp,future_timestamp,filename);
	current_index = 0;
	//generate a0
	for( int i = 0 ; i < 20 ; i++ ){
		a[i] = rand()%256;
	}
	char aw[24];
	for( int i = 0 ; i < 4 ; i++ )
		aw[i] = w[i];
	for( int i = 0 ; i < 20 ; i++ )
		aw[i+4] = a[i];
	char key[20];
	SHA1((const unsigned char *)aw,24,(unsigned char *)key);
	char * tempe1;
	char e[BUFFSIZE];
	EVP_CIPHER_CTX en,de;
	int dlength = strlen(d) + 1;
	aes_init((unsigned char *)key,20,NULL,&en,&de);
	tempe1 = (char *)aes_encrypt(&en,(unsigned char *)d,&dlength);
	//cout << tempe1 << endl;
	strcpy(e,tempe1);
	free(tempe1);
	char y[20];
	char z[20];
	for( int i = 0 ; i < 20 ; i++ ){
		y[i] = 0;
	}

	unsigned int zlength = 20;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx,a,20,EVP_sha1(),NULL);
	HMAC_Update(&ctx,(const unsigned char *)y,20);
	HMAC_Final(&ctx,(unsigned char *)z,&zlength);
	if( fprintfHex(w,e,y,z) == -1 ){
		//cout << "fail to write to file" << endl;
	};
	/*
	char tempw[4];
	char tempe[BUFFSIZE];
	char tempy[20];
	char tempz[20];
	freadHex(current_filename.c_str(),0,tempw,tempe,tempy,tempz);
	int elength = strlen(tempe);
	cout << d << endl;
	
	char * newd = (char *)aes_decrypt(&de,(unsigned char *) tempe, &elength);
	cout << newd << endl;
	free(newd);
	printf("%d\n",current_index);
	for( int i = 0 ; i < 20 ; i++ ){
		printf("%02x:",(unsigned char)a[i]);
	}
	printf("\n");
	*/
	mapalist.push_back(mapa(a,current_filename,d));
	char newa[20];
	SHA1((const unsigned char *)a,20,(unsigned char *)newa);
	for( int i = 0 ; i < 20 ; i++ )
		a[i] = newa[i];
	//DES_ecb_encrypt((C_Block *)e,(C_Block *)d,&keysched,DES_DECRYPT); 
}
void addmsg( char * msg ){
	/*
	printf("%d\n",current_index);
	for( int i = 0 ; i < 20 ; i++ ){
		printf("%02x:",(unsigned char)a[i]);
	}
	printf("\n");
	*/
	char oldw[4];
	char olde[BUFFSIZE];
	char oldy[20];
	char oldz[20];
	freadHex(current_filename.c_str(),current_index,oldw,olde,oldy,oldz);
	current_index++;
	char aw[24];
	for( int i = 0 ; i < 4 ; i++ )
		aw[i] = w[i];
	for( int i = 0 ; i < 20 ; i++ )
		aw[i+4] = a[i];
	char key[20];
	SHA1((const unsigned char *)aw,24,(unsigned char *)key);
	char * d = msg;
	EVP_CIPHER_CTX en,de;
	int dlength = strlen(d) + 1;
	aes_init((unsigned char *)key,20,NULL,&en,&de);
	char * tempe1;
	char e[BUFFSIZE];
	tempe1 = (char *)aes_encrypt(&en,(unsigned char *)d,&dlength);
	strcpy(e,tempe1);
	free(tempe1);
	int elength = strlen(e) + 1;
	char * yew = (char *)malloc(20+elength+4);
	for(int i = 0 ; i < 20 ; i++ )
		yew[i] = oldy[i];
	for( int i = 4 ; i < elength+20 ; i++ )
		yew[i] = e[i-4];
	for( int i = elength + 20 ; i < elength+4+20 ; i++ )
		yew[i] = w[i-elength-20];
	char y[20];
	char z[20];
	SHA1((const unsigned char *)yew,elength+20+4,(unsigned char *)y);
	free(yew);

	
	unsigned int zlength = 20;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx,a,20,EVP_sha1(),NULL);
	HMAC_Update(&ctx,(const unsigned char *)y,20);
	HMAC_Final(&ctx,(unsigned char *)z,&zlength);
	fprintfHex(w,e,y,z);

	/*
	char tempw[4];
	char tempe[BUFFSIZE];
	char tempy[20];
	char tempz[20];
	freadHex(current_filename.c_str(),current_index,tempw,tempe,tempy,tempz);
	int elength1 = strlen(tempe) + 1;
	cout << d <<endl;
	char * newd = (char *)aes_decrypt(&de,(unsigned char *) tempe, &elength1);
	printf("%s\n",newd);
	free(newd);
	*/
	/*
	printf("%d\n",current_index);
	for( int i = 0 ; i < 20 ; i++ ){
		printf("%02x:",(unsigned char)a[i]);
	}
	printf("\n");
	*/
	char newa[20];
	SHA1((const unsigned char *)a,20,(unsigned char *)newa);
	for( int i = 0 ; i < 20 ; i++ )
		a[i] = newa[i];
	cout <<"Added log entry number " << current_index <<endl;
}
int closelog(){
	if( current_file == NULL )
		return -1;
	int current_timestamp = (int)time(NULL);
	char oldw[4];
	char olde[BUFFSIZE];
	char oldy[20];
	char oldz[20];
	freadHex(current_filename.c_str(),current_index,oldw,olde,oldy,oldz);
	current_index++;
	char aw[24];
	for( int i = 0 ; i < 4 ; i++ )
		aw[i] = w[i];
	for( int i = 0 ; i < 20 ; i++ )
		aw[i+4] = a[i];
	char key[20];
	SHA1((const unsigned char *)aw,24,(unsigned char *)key);
	char d[BUFFSIZE];
	sprintf(d,"%d",current_timestamp);
	EVP_CIPHER_CTX en,de;
	int dlength = strlen(d) + 1;
	aes_init((unsigned char *)key,20,NULL,&en,&de);
	char * tempe1;
	char e[BUFFSIZE];
	tempe1 = (char *)aes_encrypt(&en,(unsigned char *)d,&dlength);
	strcpy(e,tempe1);
	free(tempe1);
	int elength = strlen(e) + 1;
	char * yew = (char *)malloc(20+elength+4);
	for(int i = 0 ; i < 20 ; i++ )
		yew[i] = oldy[i];
	for( int i = 4 ; i < elength+20 ; i++ )
		yew[i] = e[i-4];
	for( int i = elength + 20 ; i < elength+4+20 ; i++ )
		yew[i] = w[i-elength-20];
	char y[20];
	char z[20];
	unsigned int zlength = 20;
	SHA1((const unsigned char *)yew,elength+20+4,(unsigned char *)y);
	free(yew);

	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx,a,20,EVP_sha1(),NULL);
	HMAC_Update(&ctx,(const unsigned char *)y,20);
	HMAC_Final(&ctx,(unsigned char *)z,&zlength);
	fprintfHex(w,e,y,z);
	
	/*
	char tempw[4];
	char tempe[BUFFSIZE];
	char tempy[20];
	char tempz[20];
	freadHex(current_filename.c_str(),current_index,tempw,tempe,tempy,tempz);
	int elength1 = strlen(tempe) + 1;
	cout << strlen(d) <<endl;
	char * newd = (char *)aes_decrypt(&de,(unsigned char *) tempe, &elength1);
	cout << strlen(newd) << endl;
	free(newd);
	*/

	char newa[20];
	SHA1((const unsigned char *)a,20,(unsigned char *)newa);
	for( int i = 0 ; i < 20 ; i++ )
		a[i] = newa[i];
	fclose(current_file);
	for( list<mapa>::iterator it = mapalist.begin(); it != mapalist.end() ; it++ ){
		if( it->filename.compare(current_filename) == 0 ){
			it->set_num_entry(current_index+1);
			break;
		}
	}
	savelogs();
	/*
	printf("%d\n",current_index);
	for( int i = 0 ; i < 20 ; i++ ){
		printf("%02x:",(unsigned char)a[i]);
	}
	printf("\n");
	*/
	current_file = NULL;
	return 0;

}
int verifyall( char * logfile , char * outputfile ){
	list<string> plaintexts;
	bool haslog = false;
	mapa * m = NULL;
	for( list<mapa>::iterator it = mapalist.begin(); it != mapalist.end() ; it++ ){
		if( !it->filename.compare(logfile) && it->num_entry != -1 ){
			haslog = true;
			m = &(*it);
			break;
		}
	}
	if( !haslog ){
		cout << "Failed verification" << endl;
		return -1;
	}
	FILE * f = fopen(logfile,"r");
	if( f == NULL ){
		cout << "Failed verification" << endl;
		return -1;
	}
	char va[20];
	char w[4];
	char e[BUFFSIZE];
	char y[20];
	char z[20];
	for( int i = 0 ; i < 4 ; i++ ){
		w[i] = char2int(getc(f)) * 16;
		w[i] += char2int(getc(f));
	}
	for( int i = 0 ; i < 20 ; i++ ){
		y[i] = char2int(getc(f)) * 16;
		y[i] += char2int(getc(f));
	}
	for( int i = 0 ; i < 20 ; i++ ){
		z[i] = char2int(getc(f)) * 16;
		z[i] += char2int(getc(f));
	}
	for( int i = 0 ; i < BUFFSIZE ; i++ ){
		e[i] = char2int(getc(f)) * 16;
		e[i] += char2int(getc(f));
	}
	if( getc(f) != '\n' ){
		fclose(f);
		cout << "Failed verification" << endl;
		return -2;
	}
	for( int i = 0 ; i < 20 ; i ++ )
		va[i] = m->a0[i];
	char aw[24];
	for( int i = 0 ; i < 4 ; i++ )
		aw[i] = w[i];
	for( int i = 0 ; i < 20 ; i++ )
		aw[i+4] = va[i];
	char key[20];
	SHA1((const unsigned char *)aw,24,(unsigned char *)key);
	char * tempe1;
	EVP_CIPHER_CTX en,de;
	int dlength = strlen(m->d0) + 1;
	aes_init((unsigned char *)key,20,NULL,&en,&de);
	tempe1 = (char *)aes_encrypt(&en,(unsigned char *)m->d0,&dlength);
	if( strcmp(e,tempe1) != 0 ){
		cout << "Failed verification" << endl;
		free(tempe1);
		fclose(f);
		return -3;
	}
	free(tempe1);
	for( int i = 0 ; i < 20 ; i++ ){
		if( y[i] != 0 ){
			cout << "Failed verification" << endl;
			fclose(f);
			return -4;
		}
	}
	char tempz[20];
	unsigned int zlength = 20;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx,va,20,EVP_sha1(),NULL);
	HMAC_Update(&ctx,(const unsigned char *)y,20);
	HMAC_Final(&ctx,(unsigned char *)tempz,&zlength);
	for( int i = 0 ; i < 20 ; i++ ){
		if( z[i] != tempz[i] ){
			cout << "Failed verification" << endl;
			fclose(f);
			return -5;
		}
	}
	int templ = strlen(e) + 1;
	plaintexts.push_back(string((char *)aes_decrypt(&de,(unsigned char *)e,&templ)));
	char oldy[20];
	for( int i = 0 ; i < 20 ; i++ )
		oldy[i] = y[i];
	char newa[20];
	SHA1((const unsigned char *)va,20,(unsigned char *)newa);
	for( int i = 0 ; i < 20 ; i++ )
		va[i] = newa[i];

	for( int j = 1 ; j < m->num_entry ; j++ ){
		for( int i = 0 ; i < 4 ; i++ ){
			w[i] = char2int(getc(f)) * 16;
			w[i] += char2int(getc(f));
		}
		for( int i = 0 ; i < 20 ; i++ ){
			y[i] = char2int(getc(f)) * 16;
			y[i] += char2int(getc(f));
		}
		for( int i = 0 ; i < 20 ; i++ ){
			z[i] = char2int(getc(f)) * 16;
			z[i] += char2int(getc(f));
		}
		for( int i = 0 ; i < BUFFSIZE ; i++ ){
			e[i] = char2int(getc(f)) * 16;
			e[i] += char2int(getc(f));
		}
		if( getc(f) != '\n' ){
			cout << "Failed verification" << endl; 
			fclose(f);
			return -3;
		}
		for( int i = 0 ; i < 4 ; i++ )
			aw[i] = w[i];
		for( int i = 0 ; i < 20 ; i++ )
			aw[i+4] = va[i];
		SHA1((const unsigned char *)aw,24,(unsigned char *)key);
		int elength = strlen(e) + 1;
		char * yew = (char *)malloc(20+elength+4);
		for(int i = 0 ; i < 20 ; i++ )
			yew[i] = oldy[i];
		for( int i = 4 ; i < elength+20 ; i++ )
			yew[i] = e[i-4];
		for( int i = elength + 20 ; i < elength+4+20 ; i++ )
			yew[i] = w[i-elength-20];
		char tempy[20];
		SHA1((const unsigned char *)yew,elength+20+4,(unsigned char *)tempy);
		free(yew);
		for( int i = 0 ; i < 20 ; i++ ){
			if( tempy[i] != y[i] ){
				cout << "Failed verification" << endl;
				fclose(f);
				return -6;
			}
		}
		zlength = 20;
		HMAC_CTX_init(&ctx);
		HMAC_Init_ex(&ctx,va,20,EVP_sha1(),NULL);
		HMAC_Update(&ctx,(const unsigned char *)y,20);
		HMAC_Final(&ctx,(unsigned char *)tempz,&zlength);

		for( int i = 0 ; i < 20 ; i++ ){
			if( z[i] != tempz[i] ){
				cout << "Failed verification" << endl;
				fclose(f);
				return -5;
			}
		}
		aes_init((unsigned char *)key,20,NULL,&en,&de);
		templ = strlen(e) + 1;
		plaintexts.push_back(string((char *)aes_decrypt(&de,(unsigned char *)e,&templ)));
		SHA1((const unsigned char *)va,20,(unsigned char *)newa);
		for( int i = 0 ; i < 20 ; i++ )
			va[i] = newa[i];
		for( int i = 0 ; i < 20 ; i++ )
			oldy[i] = y[i];

	}
	FILE * out = fopen(outputfile,"w");
	if( out == NULL ){
		cout << "Failed to output file after verification" << endl;
	}
	plaintexts.pop_front();
	plaintexts.pop_back();
	for( list<string>::iterator it = plaintexts.begin()  ; it != plaintexts.end()  ; it++ ){
		fprintf(out,"%s\n",(*it).c_str());
	}
	fclose(out);
	fclose(f);
	return 0;
}
int verify( int vindex ){
	if( current_file == NULL ){
		cout << "Failed verification" << endl;
		return -1;
	}
	if( vindex <= 0 || vindex > current_index ){
		cout << "Failed verification" << endl;
		return -2;
	}
	mapa * m = NULL;
	for( list<mapa>::iterator it = mapalist.begin(); it != mapalist.end() ; it++ ){
		if( !it->filename.compare(current_filename) && it->num_entry == -1 ){
			m = &(*it);
			break;
		}
	}
	int previndex = vindex - 1;
	char w[4];
	char e[BUFFSIZE];
	char y[20];
	char z[20];
	char oldy[20];
	freadHex( current_filename , previndex , w , e , oldy ,z);
	freadHex( current_filename , vindex , w , e , y , z );
	char va[20];
	for( int i = 0 ; i < 20 ; i++ )
		va[i] = m->a0[i];
	char newa[20];
	for( int i = 0 ; i < vindex ; i++ ){
		SHA1((const unsigned char *)va,20,(unsigned char *)newa);
		for( int j = 0 ; j < 20 ; j++ )
			va[j] = newa[j];
	}
	/*
	printf("%d\n",vindex);
	for( int i = 0 ; i < 20 ; i++ ){
		printf("%02x:",(unsigned char)va[i]);
	}
	printf("\n");
	*/
	int elength = strlen(e) + 1;
	char * yew = (char *)malloc(20+elength+4);
	for(int i = 0 ; i < 20 ; i++ )
		yew[i] = oldy[i];
	for( int i = 4 ; i < elength+20 ; i++ )
		yew[i] = e[i-4];
	for( int i = elength + 20 ; i < elength+4+20 ; i++ )
		yew[i] = w[i-elength-20];
	char tempy[20];
	SHA1((const unsigned char *)yew,elength+20+4,(unsigned char *)tempy);
	free(yew);
	for( int i = 0 ; i < 20 ; i++ ){
		//printf("%02x:%02x\n",(unsigned char)y[i],(unsigned char)tempy[i]);
		
		if( tempy[i] != y[i] ){
			cout << "Failed verification" << endl;
			return -6;
		}
		
	}
	//printf("\n");
	char tempz[20];
	unsigned int zlength = 20;
	HMAC_CTX ctx; HMAC_CTX_init(&ctx); HMAC_Init_ex(&ctx,va,20,EVP_sha1(),NULL);
	HMAC_Update(&ctx,(const unsigned char *)y,20);
	HMAC_Final(&ctx,(unsigned char *)tempz,&zlength);
	for( int i = 0 ; i < 20 ; i++ ){
		if( z[i] != tempz[i] ){
			cout << "Failed verification" << endl;
			return -5;
		}
	}
	char aw[24];
	for( int i = 0 ; i < 4 ; i++ )
		aw[i] = w[i];
	for( int i = 0 ; i < 20 ; i++ )
		aw[i+4] = va[i];
	char key[20];
	SHA1((const unsigned char *)aw,24,(unsigned char *)key);
	EVP_CIPHER_CTX en,de;
	aes_init((unsigned char *)key,20,NULL,&en,&de);
	int templ = strlen(e) + 1;
	char * plaintext = (char *)aes_decrypt(&de,(unsigned char *)e,&templ);
	cout << plaintext << endl;

	return 0;
}

int main( int argc , char * args[] ){
	w[0] = 67;w[1] = 68;w[2] = 69;w[3] = 70;
	init();
	while(1){
		string input;
		char command[BUFFSIZE];
		cout << "command>";
		getline(cin,input);
		sscanf(input.c_str(),"%s",command);
		if( strcmp(command,"createlog") == 0 ){
			char filename[BUFFSIZE];
			sscanf(input.c_str(),"%s %s",command,filename);
			createlog(filename);
		}else if( strcmp(command,"add") == 0 ){
			char msg[BUFFSIZE];
			sscanf(input.c_str(),"%s %s",command,msg);
			addmsg(msg);
		}else if( strcmp(command,"closelog") == 0 ){
			closelog();
		}else if( strcmp(command,"verify") == 0 ){
			int vindex;
			sscanf(input.c_str(),"%s %d",command,&vindex);
			verify(vindex);
		}else if( strcmp(command,"verifyall") == 0 ){
			char logfile[BUFFSIZE/2];
			char outputfile[BUFFSIZE/2];
			sscanf(input.c_str(),"%s %s %s",command,logfile,outputfile);
			verifyall(logfile,outputfile);
		}else if( strcmp(command,"exit") == 0 ){
			if( current_file != NULL )
				closelog();
			exit(0);
		}else{
			cout << "invalid command : "+string(command) << endl;
		}
	}
	return 0;
}
