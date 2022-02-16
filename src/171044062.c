#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#define SIZE_OF_BLOCK 25
typedef unsigned char BYTE;
typedef unsigned long long SIZE;

/* generating a ciphertext c[0],c[1],...,c[*len_cipher-1]
 from a plaintext m[0],m[1],...,m[len_msg-1]
 associated data ad[0],ad[1],...,ad[len_ad-1]
 secret message number sec_n[0],sec_n[1],...
 public message number pub_n[0],pub_n[1],...
 secret key k[0],k[1],... */
int encryption_a(
  unsigned char *c, unsigned long long *len_cipher,
  const unsigned char *m, unsigned long long len_msg,
  const unsigned char *ad, unsigned long long len_ad,
  const unsigned char *sec_n,
  const unsigned char *pub_n,
  const unsigned char *k);

void func_permut(BYTE* state);

void lsfr(BYTE* out, BYTE* in);

void block_ad(BYTE* out, const BYTE* ad, SIZE len_ad, const BYTE* pub_num, SIZE i);

void info_block_c(BYTE* out, const BYTE* c, SIZE len_cipher, SIZE i);

#define BYTES_OF_KEYDEF 16
#define BYTES_OF_sec_n 0
#define BYTES_OF_pub_num 12
#define BYTES_OF_A 16
#define CHECK_OVERLAP 1

BYTE rotl(BYTE b);

int compare_constant(const BYTE* a, const BYTE* b, SIZE length);

/* SIZE_OF_BLOCK bytes long is needed state */
void lsfr(BYTE* out, BYTE* in);

void xor_block(BYTE* state, const BYTE* block, SIZE size);

/* Set "out" to the ith associated data block. 
 The nonce has been prepended, and padding has been provided where necessary. 
 The length of the related data in bytes is len_ad. */
void block_ad(BYTE* out, const BYTE* ad, SIZE len_ad, const BYTE* pub_num, SIZE i);

/* Returning the ith ciphertext block.
 the length of the ciphertext in bytes is len_cipher */
void info_block_c(BYTE* out, const BYTE* c, SIZE len_cipher, SIZE i);

void aead_function(
    BYTE* c, BYTE* tag, const BYTE* m, SIZE len_msg, const BYTE* ad, SIZE len_ad,
    const BYTE* pub_num, const BYTE* k, int encrypt);

/* c is at least len_msg + BYTES_OF_A long */
int encryption_a(
  unsigned char *c, unsigned long long *len_cipher,
  const unsigned char *m, unsigned long long len_msg,
  const unsigned char *ad, unsigned long long len_ad,
  const unsigned char *sec_n,
  const unsigned char *pub_num,
  const unsigned char *k);

int decryption_a(
  unsigned char *m, unsigned long long *len_msg,
  unsigned char *sec_n,
  const unsigned char *c, unsigned long long len_cipher,
  const unsigned char *ad, unsigned long long len_ad,
  const unsigned char *pub_num,
  const unsigned char *k);


typedef unsigned char BYTE;
typedef unsigned long long SIZE;
#define SIZE_OF_BLOCK 25

void func_permut(BYTE* state);

void lsfr(BYTE* out, BYTE* in);

void block_ad(BYTE* out, const BYTE* ad, SIZE len_ad, const BYTE* pub_num, SIZE i);

void info_block_c(BYTE* out, const BYTE* c, SIZE len_cipher, SIZE i);


#define index(x, y) (((x)%5)+5*((y)%5))
#define nrLanes 25
#define RoundNumMax 18

const BYTE ConstantsOfKeccak[RoundNumMax] = {
    0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
    0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

const unsigned int KeccakRhoOffsets[nrLanes] = {
    0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};

#define ROL8(a, offset) ((offset != 0) ? ((((BYTE)a) << offset) ^ (((BYTE)a) >> (sizeof(BYTE)*8-offset))) : a)

void theta(BYTE *A);

void rho(BYTE *A);

void pi(BYTE *A);

void chi(BYTE *A);

void iota(BYTE *A, unsigned int indexRound);

void KeccakP200Round(BYTE *state, unsigned int indexRound);

void func_permut(BYTE* state);

/* generating a plaintext m[0],m[1],...,m[*len_msg-1]
    and secret message number sec_n[0],sec_n[1],...
    from a ciphertext c[0],c[1],...,c[len_cipher-1]
    associated data ad[0],ad[1],...,ad[len_ad-1]
    public message number pub_num[0],pub_num[1],...
    secret key k[0],k[1],... */
int decryption_a(
  unsigned char *m, unsigned long long *len_msg,
  unsigned char *sec_n,
  const unsigned char *c, unsigned long long len_cipher,
  const unsigned char *assoc_data, unsigned long long len_ad,
  const unsigned char *pub_num,
  const unsigned char *k);


#define CRYPTO_BYTES 64
#define BYTES_OF_KEYDEF 16
#define BYTES_OF_sec_n 0
#define BYTES_OF_pub_num 12
#define BYTES_OF_A 16
#define CHECK_OVERLAP 1

void string_hexstring_conversion(unsigned char* input, int len_cipher, char* output)
{
    int loop;
    int i;

    i=0;
    loop=0;

    for (i=0;i<len_cipher;i+=2){
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;

    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}
void *hex_byte_conversion(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02hhx", &bytearray[i]);
    }

}

int main (int argc, char *argv[]) {

  unsigned long long len_msg;
  unsigned long long len_cipher;

  unsigned char cipher[CRYPTO_BYTES];
  unsigned char sec_n[BYTES_OF_A]="";
  unsigned char plaintext[CRYPTO_BYTES];
  unsigned char pub_num[BYTES_OF_pub_num]="";
  unsigned char ad[BYTES_OF_A]="";

  unsigned char key[BYTES_OF_KEYDEF];

  char pl[CRYPTO_BYTES]="BIL470";
  char chex[CRYPTO_BYTES]="";
  char keyhex[2*BYTES_OF_KEYDEF+1]="0123456789ABCDEF0123456789ABCDEF";
  char nonce[2*BYTES_OF_pub_num+1]="000000000000111111111111";
   char add[BYTES_OF_A]="BIL470";

void *hex_byte_conversion(char *hexstring, unsigned char* bytearray ) ;
  if( argc > 1 ) {
      strcpy(pl,argv[1]);
  }
  if( argc > 2 ) {
      strcpy(keyhex,argv[2]);
  }
    if( argc > 3 ) {
      strcpy(nonce,argv[3]);
  }
     if( argc > 4 ) {
      strcpy(add,argv[4]);
  }

  if (strlen(keyhex)!=32) {
	printf("************ Key length needs to be 16 bytes **************\n");
	return(0);
  }

  strcpy(plaintext,pl);
  strcpy(ad,add);
  hex_byte_conversion(keyhex,key);
  hex_byte_conversion(nonce,pub_num);

  printf("********** Given Plaintext: %s *********\n",plaintext);
  printf("********** Elephant Cipher **********\n");
  printf("******** Nonce: %s  ***********\n",nonce);
  printf("******** Key: %s    **************\n",keyhex);
  printf("******** Additional Information: %s **********\n\n",ad);

  int ret = encryption_a(cipher,&len_cipher,plaintext,strlen(plaintext),ad,strlen(ad),sec_n,pub_num,key);


string_hexstring_conversion(cipher,len_cipher,chex);

  printf("************ Cipher: %s, Len: %llu ******************\n",chex, len_cipher);

  ret = decryption_a(plaintext,&len_msg,sec_n,cipher,len_cipher,ad,strlen(ad),pub_num,key);

  printf("************** Plaintext: %s, Len: %llu *************\n",plaintext, len_msg);

  if (ret==0) {
    printf("************* Successful Operation! ****************\n");
  }

	return 0;
}

void block_ad(BYTE* output, const BYTE* ad, SIZE len_ad, const BYTE* pub_num, SIZE i)
{
    SIZE len = 0;
    // First block contains nonce
    if(i == 0) {
        memcpy(output, pub_num, BYTES_OF_pub_num);
        len += BYTES_OF_pub_num;
    }

    const SIZE block_offset = i * SIZE_OF_BLOCK - (i != 0) * BYTES_OF_pub_num;
    // if len_ad is divisible by SIZE_OF_BLOCK add an additional padding block 
    if(i != 0 && block_offset == len_ad) {
        memset(output, 0x00, SIZE_OF_BLOCK);
        output[0] = 0x01;
        return;
    }
    const SIZE r_outlen = SIZE_OF_BLOCK - len;
    const SIZE r_len_ad  = len_ad - block_offset;
    // If available fill with associated data
    if(r_outlen <= r_len_ad) { // enough AD
        memcpy(output + len, ad + block_offset, r_outlen);
    } else { // need to pad, not enough AD 
        if(r_len_ad > 0) // precaution against ad can be nullptr
            memcpy(output + len, ad + block_offset, r_len_ad);
        memset(output + len + r_len_ad, 0x00, r_outlen - r_len_ad);
        output[len + r_len_ad] = 0x01;
    }
}

BYTE rotl(BYTE b)
{
    return (b << 1) | (b >> 7);
}

int compare_constant(const BYTE* a, const BYTE* b, SIZE length)
{
    BYTE r = 0;

    for (SIZE i = 0; i < length; ++i)
        r |= a[i] ^ b[i];
    return r;
}

void lsfr(BYTE* output, BYTE* input)
{
    BYTE temp = rotl(input[0]) ^ rotl(input[2]) ^ (input[13] << 1);
    for(SIZE i = 0; i < SIZE_OF_BLOCK - 1; ++i)
        output[i] = input[i + 1];
    output[SIZE_OF_BLOCK - 1] = temp;
}

void xor_block(BYTE* state, const BYTE* block, SIZE size)
{
    for(SIZE i = 0; i < size; ++i)
        state[i] = state[i] ^ block[i];
}

void info_block_c(BYTE* output, const BYTE* c, SIZE len_cipher, SIZE i)
{
    const SIZE block_offset = i * SIZE_OF_BLOCK;
    // If len_cipher is divisible by SIZE_OF_BLOCK, add an additional padding block
    if(block_offset == len_cipher) {
        memset(output, 0x00, SIZE_OF_BLOCK);
        output[0] = 0x01;
        return;
    }
    const SIZE r_len_cipher  = len_cipher - block_offset;
    // Fill with ciphertext if available
    if(SIZE_OF_BLOCK <= r_len_cipher) { // enough ciphertext
        memcpy(output, c + block_offset, SIZE_OF_BLOCK);
    } else { // not enough ciphertext, need to pad
        if(r_len_cipher > 0) // c might be nullptr
            memcpy(output, c + block_offset, r_len_cipher);
        memset(output + r_len_cipher, 0x00, SIZE_OF_BLOCK - r_len_cipher);
        output[r_len_cipher] = 0x01;
    }
}

void aead_function(
    BYTE* c, BYTE* tag, const BYTE* m, SIZE len_msg, const BYTE* ad, SIZE len_ad,
    const BYTE* pub_num, const BYTE* k, int encrypt)
{
    // Compute number of blocks
    const SIZE nblocks_c  = 1 + len_msg / SIZE_OF_BLOCK;
    const SIZE nblocks_m  = (len_msg % SIZE_OF_BLOCK) ? nblocks_c : nblocks_c - 1;
    const SIZE nblocks_ad = 1 + (BYTES_OF_pub_num + len_ad) / SIZE_OF_BLOCK;
    const SIZE nb_it = (nblocks_c > nblocks_ad) ? nblocks_c : nblocks_ad + 1;

    /* the expanded key L storage */
    BYTE expanded_key[SIZE_OF_BLOCK] = {0};
    memcpy(expanded_key, k, BYTES_OF_KEYDEF);
    func_permut(expanded_key);

    // Buffers for storing previous, current and next mask
    BYTE buffer_masking_1[SIZE_OF_BLOCK] = {0};
    BYTE buffer_masking_2[SIZE_OF_BLOCK] = {0};
    BYTE buffer_masking_3[SIZE_OF_BLOCK] = {0};
    memcpy(buffer_masking_2, expanded_key, SIZE_OF_BLOCK);

    BYTE* previous_mask = buffer_masking_1;
    BYTE* current_mask = buffer_masking_2;
    BYTE* next_mask = buffer_masking_3;

    // Buffer to store current ciphertext block
    BYTE c_buffer[SIZE_OF_BLOCK];

    // Tag buffer and initialization of tag to zero
    BYTE tag_buffer[SIZE_OF_BLOCK] = {0};
    memset(tag, 0, BYTES_OF_A);

    SIZE offset = 0;
    for(SIZE i = 0; i < nb_it; ++i) {
        // Compute mask for the next message
        lsfr(next_mask, current_mask);

        if(i < nblocks_m) {
            // ciphertext block computation
            memcpy(c_buffer, pub_num, BYTES_OF_pub_num);
            memset(c_buffer + BYTES_OF_pub_num, 0, SIZE_OF_BLOCK - BYTES_OF_pub_num);
            xor_block(c_buffer, current_mask, SIZE_OF_BLOCK);
            func_permut(c_buffer);
            xor_block(c_buffer, current_mask, SIZE_OF_BLOCK);
            const SIZE r_size = (i == nblocks_m - 1) ? len_msg - offset : SIZE_OF_BLOCK;
            xor_block(c_buffer, m + offset, r_size);
            memcpy(c + offset, c_buffer, r_size);
        }

        if(i < nblocks_c) {
            // Compute tag of ciphertext block
            info_block_c(tag_buffer, encrypt ? c : m, len_msg, i);
            xor_block(tag_buffer, current_mask, SIZE_OF_BLOCK);
            xor_block(tag_buffer, next_mask, SIZE_OF_BLOCK);
            func_permut(tag_buffer);
            xor_block(tag_buffer, current_mask, SIZE_OF_BLOCK);
            xor_block(tag_buffer, next_mask, SIZE_OF_BLOCK);
            xor_block(tag, tag_buffer, BYTES_OF_A);
        }

        // If there is any AD left and i > 0, compute tag for AD block
        if(i > 0 && i <= nblocks_ad) {
            block_ad(tag_buffer, ad, len_ad, pub_num, i - 1);
            xor_block(tag_buffer, previous_mask, SIZE_OF_BLOCK);
            xor_block(tag_buffer, next_mask, SIZE_OF_BLOCK);
            func_permut(tag_buffer);
            xor_block(tag_buffer, previous_mask, SIZE_OF_BLOCK);
            xor_block(tag_buffer, next_mask, SIZE_OF_BLOCK);
            xor_block(tag, tag_buffer, BYTES_OF_A);
        }

        /* Cyclically shift the mask buffers
         in the next iteration, value of next_mask will be computed */
        BYTE* const temp = previous_mask;
        previous_mask = current_mask;
        current_mask = next_mask;
        next_mask = temp;

        offset += SIZE_OF_BLOCK;
    }
}

int encryption_a(
  unsigned char *c, unsigned long long *len_cipher,
  const unsigned char *m, unsigned long long len_msg,
  const unsigned char *ad, unsigned long long len_ad,
  const unsigned char *sec_n,
  const unsigned char *pub_num,
  const unsigned char *k)
{
    (void)sec_n;
    *len_cipher = len_msg + BYTES_OF_A;
    BYTE tag[BYTES_OF_A];
    aead_function(c, tag, m, len_msg, ad, len_ad, pub_num, k, 1);
    memcpy(c + len_msg, tag, BYTES_OF_A);
    return 0;
}

int decryption_a(
  unsigned char *m, unsigned long long *len_msg,
  unsigned char *sec_n,
  const unsigned char *c, unsigned long long len_cipher,
  const unsigned char *ad, unsigned long long len_ad,
  const unsigned char *pub_num,
  const unsigned char *k)
{
    (void)sec_n;
    if(len_cipher < BYTES_OF_A)
        return -1;
    *len_msg = len_cipher - BYTES_OF_A;
    BYTE tag[BYTES_OF_A];
    aead_function(m, tag, c, *len_msg, ad, len_ad, pub_num, k, 0);
    if (compare_constant(c + *len_msg, tag, BYTES_OF_A)){
        return 0;
    }
    else{
        return -1;
    }
}

void theta(BYTE *A)
{
    unsigned int x, y;
    BYTE C[5], D[5];

    for(x=0; x<5; x++) {
        C[x] = 0;
        for(y=0; y<5; y++)
            C[x] ^= A[index(x, y)];
    }
    for(x=0; x<5; x++)
        D[x] = ROL8(C[(x+1)%5], 1) ^ C[(x+4)%5];
    for(x=0; x<5; x++)
        for(y=0; y<5; y++)
            A[index(x, y)] ^= D[x];
}

void rho(BYTE *A)
{
    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            A[index(x, y)] = ROL8(A[index(x, y)], KeccakRhoOffsets[index(x, y)]);
}


void pi(BYTE *A)
{
    BYTE tempA[25];

    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            tempA[index(x, y)] = A[index(x, y)];
    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            A[index(0*x+1*y, 2*x+3*y)] = tempA[index(x, y)];
}

void chi(BYTE *A)
{
    unsigned int x, y;
    BYTE C[5];

    for(y=0; y<5; y++) {
        for(x=0; x<5; x++)
            C[x] = A[index(x, y)] ^ ((~A[index(x+1, y)]) & A[index(x+2, y)]);
        for(x=0; x<5; x++)
            A[index(x, y)] = C[x];
    }
}

void iota(BYTE *A, unsigned int indexRound)
{
    A[index(0, 0)] ^= ConstantsOfKeccak[indexRound];
}

void KeccakP200Round(BYTE *state, unsigned int indexRound)
{
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, indexRound);
}

void func_permut(BYTE* state)
{
    for(unsigned int i=0; i<RoundNumMax; i++)
        KeccakP200Round(state, i);
}