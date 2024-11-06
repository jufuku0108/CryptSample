#include "CustomCryptoService.h"

CustomCryptoService::CustomCryptoService() {
	_alg = Aes::Create();
	_alg->Mode = CipherMode::CBC;
	_alg->Padding = PaddingMode::PKCS7;
	_algKey = _alg->Key;
	_algIv = _alg->IV;
}
void CustomCryptoService::Ksa(unsigned char* key, unsigned char* state) {
	int i = 0, j = 0;
	unsigned char tmp = 0;
	for (i = 0; i < RC4_KEY_SIZE; i++) {
		state[i] = i;
	}
	int keyLen = (int)(strlen((char*)key));

	for (i = 0; i < RC4_KEY_SIZE; i++) {
		j = (j + state[i] + key[i % keyLen]) % RC4_KEY_SIZE;
		tmp = state[i];
		state[i] = state[j];
		state[j] = tmp;
	}
}

void CustomCryptoService::Prga(unsigned char* state, unsigned char* input, unsigned char* output) {
	int i = 0, j = 0;
	unsigned char tmp = 0;

	for (size_t n = 0, inputLength = strlen((char*)input); n < inputLength; n++) {
		i = (i + 1) % RC4_KEY_SIZE;
		j = (j + state[i]) % RC4_KEY_SIZE;
		unsigned char key = state[(state[i] + state[j]) % RC4_KEY_SIZE];
		tmp = state[i];
		state[i] = state[j];
		state[j] = tmp;
		output[n] = key ^ input[n];
	}
}

void CustomCryptoService::EncryptDecryptRc4(unsigned char* key, unsigned char* input, unsigned char* output) {
	unsigned char state[RC4_KEY_SIZE];
	Ksa(key, state);
	Prga(state, input, output);
}

array<Byte>^ CustomCryptoService::EncryptStringToBytesAes(String^ string) {

	MemoryStream^ mOutStream = gcnew MemoryStream();

	ICryptoTransform^ cTransform = _alg->CreateEncryptor(_algKey, _algIv);
	CryptoStream^ cStream = gcnew CryptoStream(mOutStream, cTransform, CryptoStreamMode::Write);
	StreamWriter^ sWriter = gcnew StreamWriter(cStream);
	sWriter->Write(string);
	sWriter->Close();
	cStream->Close();
	mOutStream->Close();

	array<Byte>^ encrypted = mOutStream->ToArray();
	return encrypted;

}

String^ CustomCryptoService::DecryptBytesToStringAes(array<Byte>^ bytes) {

	MemoryStream^ mInStream = gcnew MemoryStream(bytes);
	ICryptoTransform^ cTransform = _alg->CreateDecryptor(_algKey, _algIv);
	CryptoStream^ cStream = gcnew CryptoStream(mInStream, cTransform, CryptoStreamMode::Read);
	StreamReader^ sReader = gcnew StreamReader(cStream);
	String^ str = sReader->ReadToEnd();

	sReader->Close();
	cStream->Close();
	mInStream->Close();

	return str;

}

void CustomCryptoService::rc4_init(RC4_CONTEXT* a4i, const unsigned char* key, unsigned int keyLen)
{
	unsigned int keyIndex = 0, stateIndex = 0;
	unsigned int i, a;

	a4i->x = a4i->y = 0;

	for (i = 0; i < 256; i++)
		a4i->state[i] = i;

	for (i = 0; i < 256; i++)
	{
		a = a4i->state[i];
		stateIndex += key[keyIndex] + a;
		stateIndex &= 0xff;
		a4i->state[i] = a4i->state[stateIndex];
		a4i->state[stateIndex] = a;
		if (++keyIndex >= keyLen)
			keyIndex = 0;
	}
}

void CustomCryptoService::rc4_crypt(RC4_CONTEXT* a4i, unsigned char* inoutString, unsigned int length)
{
	unsigned char* const s = a4i->state;
	unsigned int x = a4i->x;
	unsigned int y = a4i->y;
	unsigned int a, b;

	while (length--)
	{
		x = (x + 1) & 0xff;
		a = s[x];
		y = (y + a) & 0xff;
		b = s[y];
		s[x] = b;
		s[y] = a;
		*inoutString++ ^= s[(a + b) & 0xff];
	}

	a4i->x = x;
	a4i->y = y;
}

NTSTATUS
WINAPI CustomCryptoService::SystemFunction032(U_STRING* data, const U_STRING* key)
{
	RC4_CONTEXT a4i;

	rc4_init(&a4i, key->Buffer, key->Length);
	rc4_crypt(&a4i, data->Buffer, data->Length);

	return STATUS_SUCCESS;
}




void CustomCryptoService::Permute(unsigned char* dst, const unsigned char* src, const unsigned char* map, const int mapsize)
{
	int bitcount, i;

	for (i = 0; i < mapsize; i++)
		dst[i] = 0;

	bitcount = mapsize * 8;

	for (i = 0; i < bitcount; i++)
	{
		if (GETBIT(src, map[i]))
			SETBIT(dst, i);
	}
}

void CustomCryptoService::Xor(unsigned char* dst, const unsigned char* a, const unsigned char* b, const int count)
{
	int i;

	for (i = 0; i < count; i++)
		dst[i] = a[i] ^ b[i];
}

void CustomCryptoService::Sbox(unsigned char* dst, const unsigned char* src)
{
	int i;

	for (i = 0; i < 4; i++)
		dst[i] = 0;

	for (i = 0; i < 8; i++)
	{
		int j, Snum, bitnum;

		for (Snum = j = 0, bitnum = (i * 6); j < 6; j++, bitnum++)
		{
			Snum <<= 1;
			Snum |= GETBIT(src, bitnum);
		}

		if (0 == (i % 2))
			dst[i / 2] |= ((SBox[i][Snum]) << 4);
		else
			dst[i / 2] |= SBox[i][Snum];
	}
}

void CustomCryptoService::KeyShiftRight(unsigned char* key, const int numbits)
{
	int i;
	unsigned char keep = key[6];

	for (i = 0; i < numbits; i++)
	{
		int j;

		for (j = 6; j >= 0; j--)
		{
			if (j != 6 && (key[j] & 0x01))
				key[j + 1] |= 0x80;
			key[j] >>= 1;
		}

		if (GETBIT(key, 28))
		{
			CLRBIT(key, 28);
			SETBIT(key, 0);
		}

		if (keep & 0x01)
			SETBIT(key, 28);

		keep >>= 1;
	}
}

unsigned char* CustomCryptoService::CRYPT_DESunhash(unsigned char* dst, const unsigned char* key,const unsigned char* src)
{
	int i;
	unsigned char K[7];
	unsigned char D[8];

	Permute(K, key, KeyPermuteMap, 7);
	Permute(D, src, InitialPermuteMap, 8);

	for (i = 0; i < 16; i++)
	{
		int j;
		unsigned char* L = D;
		unsigned char* R = &(D[4]);
		unsigned char  Rexp[6];
		unsigned char  Rn[4];
		unsigned char  SubK[6];

		Permute(SubK, K, KeyCompression, 6);

		Permute(Rexp, R, DataExpansion, 6);
		Xor (Rexp, Rexp, SubK, 6);

		Sbox(Rn, Rexp);
		Permute(Rexp, Rn, PBox, 4);
		Xor (Rn, L, Rexp, 4);

		for (j = 0; j < 4; j++)
		{
			L[j] = R[j];
			R[j] = Rn[j];
		}

		KeyShiftRight(K, KeyRotation[15 - i]);
	}

	Permute(dst, D, FinalPermuteMap, 8);

	return dst;
}

NTSTATUS
WINAPI CustomCryptoService::SystemFunction025(const BYTE* in, const BYTE* key, LPBYTE out)
{
	BYTE deskey[0x10];

	memcpy(deskey, key, 4);
	memcpy(deskey + 4, key, 4);
	memcpy(deskey + 8, key, 4);
	memcpy(deskey + 12, key, 4);

	CRYPT_DESunhash(out, deskey, in);
	CRYPT_DESunhash(out + 8, deskey + 7, in + 8);

	return STATUS_SUCCESS;
}
