#include<stdio.h>
#include<malloc.h>
#include<string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include<limits.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#define STRING12CHARS "characters12"

void test_bad_free () {
    char *str = NULL;
    str = "Non dynamic memory allocation";
    free(str);
}

void test_bad_cmp_func_add () {
    /* Function ddress will always evaluate to true */
    if (test_bad_free != 0) {
        printf("Always evaluates to true\n");
    }
}

void test_bad_cmp_inequality_with_null () {
    char *str = malloc(10);
    if (str > 0) {
       printf("Pointer should be be compared using == or !=\n");
    }
    if (str) {
       free(str);
    }
}

void bad_cmp_ptr_comparison_with_string_literal () {
    char a[] = "T";
    if (a == "T") {
       printf("This should not work\n");
    } else if (strcmp(a, "T") == 0) {
       printf("This should work\n");
    }
}

void bad_sizeof_pointer () {
    char src_string[19]="Bad_SizeOf_example", out_string[19];
    char *ptr = NULL;
    ptr = src_string;
    memcpy(out_string, src_string, sizeof(ptr));
    printf("Out_String=%s\n",out_string);
}

int bad_sizeof_expression (int i) {
  int intArray[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
  int *intPointer = intArray;
  /* BAD: the offset is already automatically scaled by sizeof(int),
     so this code will compute the wrong offset. */
  return *(intPointer + (i * sizeof(int)));
  /* Right expression
  return *(intPointer + i);
  */
}

void test_buf_size_possible_overflow () {
    char password[10];
    printf("Buffer overflow if password more than 9 characters\n");
    gets(password);
}

void test_buf_size_copy_into_fixed_size_buffer () {
    char dst[10];
    strcpy(dst, "morethan10characters");
}

void test_buf_size_dest_buff_too_small () {
    char dst[5];
    char src[10] = "characters";
    strcpy (dst, src);
}

void test_buf_size_overlap_mem () {
    char list[10] ="eightfive";
    memcpy(list, list+1, 10);
}

void test_buf_size_not_null_terminated () {
    char dst[10];
    strncpy(dst, STRING12CHARS, 10);
}
 
void test_insecure_chroot () {
    int i;
    mkdir("breakout", 0700);
    chroot("breakout");
    for (i = 0; i < 100; i++)
       chdir("..") ;
    chroot(".");
    execl("/bin/sh", "/bin/sh",NULL);
}

void test_risky_function1 () {
    char buf[10];
    scanf("%s", buf);
}

void test_risky_function2 () {
   char str[10];
   FILE * fp;

   fp = fopen ("file.txt", "w+");
   fputs("HakunnahMatata!", fp);
   rewind(fp);
   fscanf(fp, "%s", str);
   
   printf("Read String |%s|\n", str);
   fclose(fp);
}

void test_risky_weak_crypto () {
  char id[20]; 
  int r;
  r = rand();  /* Generate a random integer */
  snprintf(id, 10, "ID%-d", r);
}

void test_hardcoded_key (char *key) {
    char password[10] = "abcdefg";
    if (strcmp(password, key)) {
        printf("Incorrect Password!\n");
    } else {
       printf("Entering Diagnostic Mode...\n");
    }
}

void test_int_overflow_index_read () {
    int arr[6] = {0,1,2,3,4,5};
    int elem;

    elem =  arr[7];
    printf("Elem %d\n", elem);
}

void test_int_overflow_index_write () {
    int arr[6] = {0,1,2,3,4,5};

    arr[7] = 7;
    printf("Elem %d\n", arr[7]);
}

void test_overflow_const () {
    int x = (8 * (512 * 786432) * 32768);
    printf("%d\n", x);
}

void test_int_overflow_ptr_read () {
    int arr[6] = {0,1,2,3,4,5};

    printf("Elem at index 7 %d\n", *(arr+7));
}

void test_int_overflow_ptr_write () {
    int arr[6] = {0,1,2,3,4,5};
    *(arr + 7) = 7;
    printf("Elem at index 7 %d\n", *(arr+7));
}

unsigned int test_int_return_overflow (double value)
{
    unsigned int  intpart = ((unsigned int)value);
    return ((value -= intpart) < 0.5) ? intpart : intpart + 1;
}

void test_overflow_argument () {
    int *grab_some_memory;
    int page_size;
    int num_pages;
    printf("Page size ?\n");
    scanf("%d", &page_size);
    printf("Num Pages?\n");
    scanf("%d", &num_pages);
    grab_some_memory = (int *)malloc(page_size * num_pages);
}

void test_int_overflow () {
    char data;
    scanf ("%c", &data);
    /* POTENTIAL FLAW: Adding 1 to data could cause an overflow */
    char result = data + 1;
    printf("%d\n", result);
}

void test_negative_returns () {     
    int a[] = {0,1,2,3,4,5};
    int i= -1;
    printf("%d",a[i]);
}

void test_insecure_file_perms () {
    umask(0);
    FILE *out;
    out = fopen("hello.txt", "w");
    if (out) {
        fprintf(out, "hello world!\n");
        fclose(out);
    }
}

void test_risky_crypto_function () {
    unsigned char *plaintext = "mihirshirali";
    int plaintext_len = strlen ((char *)plaintext);
    unsigned char *key = (unsigned char *)"01234567";
    unsigned char ciphertext[128];

    int len;
    int ciphertext_len;

    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return;

    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, NULL))
        return;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    printf("Cipher text length %d:%s" , ciphertext_len, ciphertext);
}

void test_risky_crypto_hash_function () {
    const char *str = "hello";
    int length = strlen(str);
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *out = (char*)malloc(33);

    MD5_Init(&c);

    while (length > 0) {
        if (length > 512) {
            MD5_Update(&c, str, 512);
        } else {
            MD5_Update(&c, str, length);
        }
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }
    
    printf("Digest:%s\n", out);
    if (out) 
       free(out);
}

void main () {
    printf("Starting all tests\n");
    printf("1 - Bad free\n");
    test_bad_free();
    printf("2 - Bad Compare Function address comparison\n");
    test_bad_cmp_func_add();
    printf("3 - Bad Compare Inequality comparison against NULL\n");
    test_bad_cmp_inequality_with_null(); 
    printf("4 - Bad Compare ptr with string literal\n");
    bad_cmp_ptr_comparison_with_string_literal();
    printf("5 - Bad sizeof pointer\n");
    bad_sizeof_pointer();
    printf("6 - Bad sizeof expression\n");
    printf("%d\n", bad_sizeof_expression(6));
    printf("7 - Buffer size possible overflow\n");
    test_buf_size_possible_overflow();
    printf("8 - Buffer size copy into fixed size buffer\n");
    test_buf_size_copy_into_fixed_size_buffer();
    printf("9 - Buffer overflow  dest buff too small\n");
    test_buf_size_dest_buff_too_small();
    printf("10 -  Buffer overflow  dest buff too small\n");
    test_buf_size_dest_buff_too_small(); 
    printf("11 - Buffer overflow - overlapping memory in memcpy\n");
    test_buf_size_overlap_mem();
    printf("12 - Buffer overflow - Buffer not null terminated\n"); 
    test_buf_size_not_null_terminated();
    printf("13 - Insecure chroot\n");
    test_insecure_chroot();
    printf("14 - Calling risky function buffer\n");
    test_risky_function1();
    printf("15 - Calling risky function stream\n");
    test_risky_function2();
    printf("16 - Calling risky function weak crypto\n");
    test_risky_weak_crypto();
    printf("17 - Use hard coded cryptographic key\n");
    //https://cwe.mitre.org/data/definitions/321.html
    test_hardcoded_key("68af404b513073584c4b6f22b6c63e6b");
    printf("18 - Use hard coded password\n");
    //https://cwe.mitre.org/data/definitions/259.html
    test_hardcoded_key("Mew!");
    printf("19 - Use hard coded credentials\n");
    //https://cwe.mitre.org/data/definitions/798.html
    test_hardcoded_key("Woof!");
    printf("20 - Use hard coded security token\n");
    //Could not find CWE. Should be same as above, except credential is not a token instead of password
    test_hardcoded_key("tokenIssuesToUserA");
    printf("21 - Overﬂowed array index read\n");
    test_int_overflow_index_read();
    printf("22 - Overﬂowed array index write\n");
    test_int_overflow_index_write();
    printf("23 - Overflowed constant\n");
    test_overflow_const();
    printf("24 - Integer overflowed argument\n");
    //Ref https://github.com/radare/radare2/issues/1548
    test_overflow_argument();
    printf("25 - Overﬂowed pointer read\n");
    test_int_overflow_ptr_read();
    printf("26 - Overﬂowed pointer write\n");
    test_int_overflow_ptr_write();
    printf("27 - Overﬂowed integer return\n");
    //Ref: https://github.com/weiss/c99-snprintf/issues/1
    unsigned int a = test_int_return_overflow(10.70);
    printf("28 - Overflowed integer\n");
    test_int_overflow();
    printf("29 - Negative returns\n");
    //https://community.synopsys.com/s/article/From-Case-OVERRUN-defects-for-indexing-array-with-value-0
    test_negative_returns();
    printf("30 - Test insecure file perms\n");
    test_insecure_file_perms();
    printf("31 - Test risky crypto function\n");
    test_risky_crypto_function();
    printf("32 - Test risky crypto hash function\n");
    test_risky_crypto_hash_function();
}
