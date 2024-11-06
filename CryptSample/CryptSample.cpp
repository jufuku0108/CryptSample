// CryptSample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "CustomCryptoService.h"


int main()
{
    CustomCryptoService^ cs = gcnew CustomCryptoService();
    
    Console::WriteLine("---Using AES---");
    String^ aInput = "Hello encrypted world";
    Console::WriteLine("Input text : " + aInput);
    
    // encrypt
    array<Byte>^ aesEncrypted = cs->EncryptStringToBytesAes(aInput);
    printf("Encrypted text : ");
    for (int i = 0; i < aesEncrypted->Length; i++) {
        printf("%02hhX", (char)aesEncrypted[i]);
    }
    printf("\n");

    // decrypt
    String^ str = cs->DecryptBytesToStringAes(aesEncrypted);
    Console::WriteLine("Decrypted text : " + str);


    printf("---Using RC4---\n");
    unsigned char* input = (unsigned char*)"Hello encrypted world";
    printf("Input tex t: %s\n", (char*)input);
    
    // encrypt
    unsigned char* key = (unsigned char*)"tmpKey";
    size_t inputSize = sizeof(char) * strlen((char*)input);
    unsigned char* rc4Encrypted = (unsigned char*)calloc(inputSize + 1, sizeof(unsigned char));

    cs->EncryptDecryptRc4(key, input, rc4Encrypted);
    printf("Encrypted text : ");
    for (size_t i = 0; i < inputSize; i++) {
        printf("%02hhX", (char)rc4Encrypted[i]);
    }
    printf("\n");
    
    // decrypt
    unsigned char* rc4Decrypted = (unsigned char*)calloc(inputSize + 1, sizeof(unsigned char));
    cs->EncryptDecryptRc4(key, rc4Encrypted, rc4Decrypted);
    printf("Decrypted text : %s\n", (char*)rc4Decrypted);


    printf("---Using SystemFunction032---\n");
    unsigned char sInputtext[] = "inputdata";
    printf("Input text : %s\n", (char*)sInputtext);

    // encrypt
    size_t sInputtextSize = sizeof(char) * strlen((char*)sInputtext);
    U_STRING sInOutStruct = { sInputtextSize, sInputtextSize, (PUCHAR)&sInputtext };

    unsigned char sKey[] = "inputkey";
    size_t sKeySize = sizeof(char) * strlen((char*)sKey);
    U_STRING sKeyStruct = { sKeySize, sKeySize, (PUCHAR)&sKey };

    cs->SystemFunction032(&sInOutStruct, &sKeyStruct);

    printf("Encrypted text : ");
    for (size_t i = 0; i < sInOutStruct.Length; i++) {
        printf("%02hhX", sInOutStruct.Buffer[i]);
    }
    printf("\n");

    // decrypt
    cs->SystemFunction032(&sInOutStruct, &sKeyStruct);
    printf("Decrypted text : %s\n", sInOutStruct.Buffer);




    printf("---Using SystemFunction025---\n");
    unsigned char s25Inputtext[] = "abcdefghijklmnop";
    printf("Input text : %s\n", (char*)s25Inputtext);

    unsigned char s25Key[] = "512";

    unsigned char s25Outputtext[16];
    cs->SystemFunction025(s25Inputtext, s25Key, s25Outputtext);

    printf("Encrypted text : ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02hhX", s25Outputtext[i]);
    }
    printf("\n");
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
