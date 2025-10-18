#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <array>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <stdexcept>

using ByteStream = std::vector<uint8_t>;

// Initial values defined by SHA-256 specification
const std::array<uint32_t, 8> InitialDigest = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Here are the constants for each SHA-256 compression round
const std::array<uint32_t, 64> RoundConstants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Bitwise rotation to the right
uint32_t rotateRight(uint32_t value, int bits) {
    return (value >> bits) | (value << (32 - bits));
}

// These are SHA-256 logic functions (Ch, Maj, and Σ variants)
uint32_t select(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t upperSigma0(uint32_t x) {
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

uint32_t upperSigma1(uint32_t x) {
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

uint32_t lowerSigma0(uint32_t x) {
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

uint32_t lowerSigma1(uint32_t x) {
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

// Here we should give Padding input to conform to SHA-256 block size
ByteStream prepareInput(const std::string& inputText) {
    ByteStream bytes(inputText.begin(), inputText.end());
    uint64_t bitLen = static_cast<uint64_t>(bytes.size()) * 8;

    // Append a single '1' bit (as 0x80)
    bytes.push_back(0x80);

    // We should pad with zeros till we reach 56 bytes mod 64
    while ((bytes.size() * 8 + 64) % 512 != 0) {
        bytes.push_back(0x00);
    }

    // Appending the original message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        bytes.push_back((bitLen >> (i * 8)) & 0xFF);
    }

    return bytes;
}

// Here is the processes input in 512-bit blocks and updates digest state
std::array<uint32_t, 8> computeHashBlocks(const ByteStream& data) {
    std::array<uint32_t, 8> digestState = InitialDigest;

    for (size_t i = 0; i < data.size(); i += 64) {
        std::array<uint32_t, 64> schedule{};

        // To get initial 16 words from the message block
        for (int j = 0; j < 16; ++j) {
            schedule[j] = (data[i + j * 4] << 24) | (data[i + j * 4 + 1] << 16) |
                          (data[i + j * 4 + 2] << 8) | (data[i + j * 4 + 3]);
        }

        // To Expand the message schedule
        for (int j = 16; j < 64; ++j) {
            schedule[j] = lowerSigma1(schedule[j - 2]) + schedule[j - 7] +
                          lowerSigma0(schedule[j - 15]) + schedule[j - 16];
        }

        // Assigned working variables from the current hash state
        uint32_t a = digestState[0], b = digestState[1], c = digestState[2], d = digestState[3];
        uint32_t e = digestState[4], f = digestState[5], g = digestState[6], h = digestState[7];

        // Main compression loop
        for (int j = 0; j < 64; ++j) {
            uint32_t temp1 = h + upperSigma1(e) + select(e, f, g) + RoundConstants[j] + schedule[j];
            uint32_t temp2 = upperSigma0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Update hash state
        digestState[0] += a; digestState[1] += b; digestState[2] += c; digestState[3] += d;
        digestState[4] += e; digestState[5] += f; digestState[6] += g; digestState[7] += h;
    }

    return digestState;
}

// Below line of code converts the hash state to a hexadecimal string
std::string convertToHexDigest(const std::array<uint32_t, 8>& state) {
    std::stringstream hexStream;
    for (uint32_t part : state) {
        hexStream << std::hex << std::setw(8) << std::setfill('0') << part;
    }
    return hexStream.str();
}

// This is a high-level SHA-256 interface function
std::string generateSha256Hash(const std::string& text) {
    ByteStream inputBytes = prepareInput(text);
    std::array<uint32_t, 8> hashState = computeHashBlocks(inputBytes);
    return convertToHexDigest(hashState);
}

// The below line loads the entire contents of a file into a string
std::string loadFileContents(const std::string& filePath) {
    std::ifstream input(filePath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
    return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

int main() {
    try {
        // Path to the text of the book of Mark (adjust as needed)
        std::string filePath = "Mark_textbook.txt";
        std::cout << "Loading text from file: " << filePath << "\n";

        std::string fullText = loadFileContents(filePath);
        std::cout << "Text loaded successfully. Character count: " << fullText.length() << "\n";

        std::string finalHash = generateSha256Hash(fullText);
        std::cout << "Computed SHA-256 Hash: " << finalHash << "\n";
    }
    catch (const std::exception& error) {
        std::cerr << "Execution failed: " << error.what() << "\n";
        return 1;
    }

    return 0;
}
