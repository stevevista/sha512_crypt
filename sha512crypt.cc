

#include <v8.h>
#include <errno.h>
#include <nan.h>
#include <openssl/evp.h>

using namespace v8;

#define MAX_BUFFER_SIZE (64*3)


static bool initCtx(const EVP_MD* md, EVP_MD_CTX* ctx) {
	EVP_MD_CTX_init(ctx);
  	if (EVP_DigestInit_ex(ctx, md, nullptr) <= 0) {
    	return false;
  	}
	return true;
}


struct buffer {
	buffer() : size(0) {}
	buffer(const char* src) {
		size = strlen(src);
		memcpy(d, src, size);
	}
	buffer(const buffer& src) {
		size = src.size;
		memcpy(d, src.d, size);
	}
	unsigned char* end() { return &d[size]; }
	buffer& concat(const buffer& other) {
		memcpy(end(), other.d, other.size);
		size += other.size;
		return *this;
	}
	unsigned int size;
	unsigned char d[MAX_BUFFER_SIZE];
};

static void ctxUpdate(EVP_MD_CTX* ctx, const buffer& source) {
	EVP_DigestUpdate(ctx, source.d, source.size);
}

static void ctxDigest(EVP_MD_CTX* ctx, buffer& value) {
	EVP_DigestFinal_ex(ctx, value.d, &value.size);
  	EVP_MD_CTX_cleanup(ctx);
}

static void ctxDigest(const EVP_MD* md, buffer& target, const buffer& source0, const buffer& source1) {
	EVP_MD_CTX ctx;
	if (!initCtx(md, &ctx))
		return;
	ctxUpdate(&ctx, source0);
	ctxUpdate(&ctx, source1);
	ctxDigest(&ctx, target);
}

static void ctxDigest(const EVP_MD* md, buffer& target, const buffer& source0, const buffer& source1, const buffer& source2) {
	EVP_MD_CTX ctx;
	if (!initCtx(md, &ctx))
		return;
	ctxUpdate(&ctx, source0);
	ctxUpdate(&ctx, source1);
	ctxUpdate(&ctx, source2);
	ctxDigest(&ctx, target);
}


static void digestMutiple(const EVP_MD* md, buffer& target, const buffer& source, int count) {
	EVP_MD_CTX ctx;
	if (!initCtx(md, &ctx))
		return;

	for (int i=0; i<count; i++)
		ctxUpdate(&ctx, source);
	ctxDigest(&ctx, target);
}


static void extend(buffer& target, const buffer& source, unsigned int size_ref) {
    
	unsigned int chunk = size_ref/64;
	unsigned int tail = size_ref % 64;

    for (unsigned int i=0;i<chunk;i++) {
		target.concat(source);
	}
	
	if (tail > 0) {
		memcpy(target.end(), source.d, tail);
		target.size += tail;
	}
}


const char* CHARSET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void gensalt(char* s) {
	srand( (unsigned int)time(0) );
    for (int i = 0; i < 16; i++){
        s[i] = CHARSET[rand()%64];
    }
	s[16] = 0;
}

unsigned int b64encode(char* output, const buffer& input) {
	const int order[] = { 42, 21, 0,
                  1,  43, 22,
                  23, 2,  44,
                  45, 24, 3,
                  4,  46, 25,
                  26, 5,  47,
                  48, 27, 6,
                  7,  49, 28,
                  29, 8,  50,
                  51, 30, 9,
                  10, 52, 31,
                  32, 11, 53,
                  54, 33, 12,
                  13, 55, 34,
                  35, 14, 56,
                  57, 36, 15,
                  16, 58, 37,
                  38, 17, 59,
                  60, 39, 18,
                  19, 61, 40,
                  41, 20, 62,
                  63};

	int n = 0;
    for (unsigned int i=0; i < input.size; i+=3) {
		// special case for the end of the input
        if (i+2>= input.size) {
			unsigned char v1 = input.d[order[i]];
			if (i+1>= input.size) {
				output[n++] = CHARSET[v1 & 0x3f];
				output[n++] = CHARSET[v1>>6];
			} else {
				unsigned char v2 = input.d[order[i+1]];
				output[n++] = CHARSET[v1 & 0x3f];
				output[n++] = CHARSET[((v2 & 0x0f)<<2)|(v1>>6)];
				output[n++] = CHARSET[v2>>4];
			}
        } else {
			unsigned char v1 = input.d[order[i]];
			unsigned char v2 = input.d[order[i+1]];
			unsigned char v3 = input.d[order[i+2]];
			output[n++] = CHARSET[v1 & 0x3f];
			output[n++] = CHARSET[((v2 & 0x0f)<<2)|(v1>>6)];
			output[n++] = CHARSET[((v3 & 0x03)<<4)|(v2>>4)];
			output[n++] = CHARSET[v3>>2];
		}
	}

	output[n] = 0;

	return n;
}

unsigned int shacrypt(const char* hashType, char* output, const char* apassword, const char* inputsalt, int rounds) {

	const EVP_MD* md = EVP_get_digestbyname(hashType);
	if (md == nullptr)
    	return 0;

	char randSalt[17];

	if (rounds < 1000)
		rounds = 1000;
	if (rounds > 1000000)
		rounds = 1000000;

	const char* asalt = inputsalt;
	if (!inputsalt || strlen(inputsalt) == 0) {
		gensalt(randSalt);
		
		asalt = randSalt;
	}

	const buffer password(apassword);
	const buffer salt(asalt);

	// steps 1-12
	buffer digest_b;
	ctxDigest(md, digest_b, password, salt, password);

	// extend digest b so that it has the same size as password
	buffer digest_b_extended;
    extend(digest_b_extended, digest_b, password.size);

	EVP_MD_CTX ctx;
	if (!initCtx(md, &ctx))
		return 0;
	ctxUpdate(&ctx, password);
	ctxUpdate(&ctx, salt);
	ctxUpdate(&ctx, digest_b_extended);
    for (unsigned int cnt = password.size; cnt > 0; cnt >>= 1) {
		ctxUpdate(&ctx, (cnt & 1) ? digest_b : password);
    }
	buffer digest_a;
    ctxDigest(&ctx, digest_a);

	// step 13-15
	buffer dp;
	digestMutiple(md, dp, password, password.size);

    // step 16
	buffer p;
    extend(p, dp, password.size);

	// step 17-19
	buffer ds;
	digestMutiple(md, ds, salt, 16+digest_a.d[0]);

    // step 20
	buffer s;
    extend(s, ds, salt.size);

	buffer perms[6];
	perms[0].concat(p);
	perms[1].concat(p).concat(p);
	perms[2].concat(p).concat(s);
	perms[3].concat(p).concat(s).concat(p);
	perms[4].concat(s).concat(p);
	perms[5].concat(s).concat(p).concat(p);


	const int c_digest_offsets[][2] = {
        {0, 3}, {5, 1}, {5, 3}, {1, 2}, {5, 1}, {5, 3}, {1, 3},
        {4, 1}, {5, 3}, {1, 3}, {5, 0}, {5, 3}, {1, 3}, {5, 1},
        {4, 3}, {1, 3}, {5, 1}, {5, 2}, {1, 3}, {5, 1}, {5, 3},
	};

	const buffer* data[21][2];
	for (int i=0; i<21; i++) {
		int even = c_digest_offsets[i][0];
		int odd = c_digest_offsets[i][1];
		data[i][0] = &perms[even];
		data[i][1] = &perms[odd];
	}

	// step 21
	buffer digest(digest_a);
    for (int i=0;i<rounds/42;i++) {
		for (int n=0; n<21; n++) {
			const buffer* even = data[n][0];
			const buffer* odd = data[n][1];
			buffer tmp;
			ctxDigest(md, tmp, digest, *even);
			ctxDigest(md, digest, *odd, tmp);
		}
    }

	int tail = rounds % 42;
    if (tail > 0) {
        int pairs = tail>>1;
		for (int n = 0; n<pairs; n++) {
			const buffer* even = data[n][0];
			const buffer* odd = data[n][1];
			buffer tmp;
			ctxDigest(md, tmp, digest, *even);
			ctxDigest(md, digest, *odd, tmp);
		}
        if (tail & 1) {
			ctxDigest(md, digest, digest, *data[pairs][0]);
		}
    }

	sprintf(output, "$6$rounds=%d$%s$", rounds, asalt);
	int len = strlen(output);
	return b64encode(&output[len], digest);
}

NAN_METHOD(Method) {
	Nan::HandleScope scope;

	if (info.Length() < 3) {
		return Nan::ThrowTypeError("Need 3 arguments");
	}

	if (!info[0]->IsString() || !info[1]->IsString() || !info[2]->IsInt32()) {
		return Nan::ThrowTypeError("wrong paramters type");
	}

	v8::String::Utf8Value key(info[0]->ToString());
	v8::String::Utf8Value salt(info[1]->ToString());
	int rounds = info[2]->Int32Value();

	if (key.length() > 64) {
		return Nan::ThrowTypeError("key length at most 64");
	}

	if (salt.length() > 64) {
		return Nan::ThrowTypeError("salt length at most 64");
	}

	char digest[128]= "";
	shacrypt("sha512", digest, *key, *salt, rounds);
	info.GetReturnValue().Set(Nan::New<String>(digest).ToLocalChecked());
}


void init(Handle<Object> exports) {
	exports->Set(Nan::New<String>("crypt").ToLocalChecked(),
		Nan::New<FunctionTemplate>(Method)->GetFunction());
}

NODE_MODULE(sha512_crypt, init)

/* EOF */
