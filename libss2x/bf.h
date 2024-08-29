#ifndef BF_H
#define BF_H

#include <cstdint>
#include <cstring>

#include <arpa/inet.h>

namespace ss::bf {

typedef union {
	std::uint8_t inb[8];
	struct {
		std::uint32_t L;
		std::uint32_t R;
	};
} block_t;

class block {
	// original contents of P/S boxes
	static const std::uint32_t ORIG_P[16 + 2];
	static const std::uint32_t ORIG_S[4][256];

	// P/S boxes
	std::uint32_t P[16 + 2];
	std::uint32_t S[4][256];

	// 16 rounds is standard
	static const int ROUNDS = 16;

	// private internal routines
	std::uint32_t F(std::uint32_t x);
	void Blowfish_Encrypt(std::uint32_t *xl, std::uint32_t *xr);
	void Blowfish_Decrypt(std::uint32_t *xl, std::uint32_t *xr);
	void Blowfish_Init(const std::uint8_t *key, int keyLen);

public:
	block(const std::uint8_t *a_buffer, std::uint8_t *a_key, std::size_t a_key_len);
	void set_blockdata(const std::uint8_t *a_buffer);
	const std::uint8_t *get_blockdata() const { return (const std::uint8_t *)m_block.inb; }
	void set_iv(const std::uint8_t *a_iv);

	void encrypt();
	void decrypt();

	void encrypt_with_cbc();
	void decrypt_with_cbc();

protected:
	block_t m_block;
	std::uint8_t m_iv[8];
};
	
}; // namespace ss::bf

#endif // BF_H
