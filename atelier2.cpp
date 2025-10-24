
#include <sstream>
#include <iomanip>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <random>
#include <bitset>
#include <iomanip>
#include <sstream>   
#include <numeric>
#include <chrono>
#include <ctime>
#include <cstdint>
using namespace std;


using namespace std;
using namespace std::chrono;

//////////////////////////////////////
// Partie 1 : Automate cellulaire
//////////////////////////////////////

vector<int> init_state(const string& bits) {
    vector<int> state;
    for (char c : bits) state.push_back(c - '0');
    return state;
}

vector<int> evolve(const vector<int>& state, int rule) {
    int n = state.size();
    vector<int> new_state(n, 0);
    for (int i = 0; i < n; ++i) {
        int left = (i == 0) ? state[n - 1] : state[i - 1];
        int center = state[i];
        int right = (i == n - 1) ? state[0] : state[i + 1];
        int pattern = (left << 2) | (center << 1) | right;
        new_state[i] = (rule >> pattern) & 1;
    }
    return new_state;
}

void affichage(const vector<int>& state) {
    for (int bit : state) cout << (bit ? "*" : " ");
    cout << endl;
}

//////////////////////////////////////
// Partie 2 : AC_HASH (Automate)
//////////////////////////////////////

vector<int> text_to_bits(const string& input) {
    vector<int> bits;
    for (unsigned char c : input)
        for (int i = 7; i >= 0; --i)
            bits.push_back((c >> i) & 1);
    return bits;
}

string ac_hash(const string& input, uint32_t rule, size_t steps) {
    vector<int> state = text_to_bits(input);
    if (state.size() < 256) state.resize(256, 0);
    else if (state.size() > 256) state.resize(256);
    for (size_t i = 0; i < steps; ++i) state = evolve(state, rule);
    string hash = "";
    for (int bit : state) hash += (bit ? '1' : '0');
    return hash;
}

//////////////////////////////////////
// Partie 3 : SHA256 pur (sans OpenSSL)
//////////////////////////////////////

namespace SimpleSHA256 {

typedef uint32_t u32;
typedef uint64_t u64;

inline u32 rotr(u32 x, u32 n) { return (x >> n) | (x << (32 - n)); }

string sha256(const string& input) {
    vector<uint8_t> data(input.begin(), input.end());
    u64 bitlen = data.size() * 8;

    // Padding
    data.push_back(0x80);
    while ((data.size() % 64) != 56) data.push_back(0x00);
    for (int i = 7; i >= 0; --i) data.push_back((bitlen >> (i * 8)) & 0xff);

    u32 h[] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    const u32 k[] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
        u32 w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (data[chunk + 4*i] << 24) | (data[chunk + 4*i + 1] << 16) |
                   (data[chunk + 4*i + 2] << 8) | (data[chunk + 4*i + 3]);
        for (int i = 16; i < 64; ++i)
            w[i] = w[i-16] + (rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3))
                 + w[i-7] + (rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10));

        u32 a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];

        for (int i = 0; i < 64; ++i) {
            u32 S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            u32 ch = (e & f) ^ ((~e) & g);
            u32 temp1 = hh + S1 + ch + k[i] + w[i];
            u32 S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            u32 maj = (a & b) ^ (a & c) ^ (b & c);
            u32 temp2 = S0 + maj;
            hh = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    stringstream ss;
    for (int i = 0; i < 8; ++i)
        ss << hex << setw(8) << setfill('0') << h[i];
    return ss.str();
}

} 

//////////////////////////////////////
// Partie 4 : Blockchain
//////////////////////////////////////

enum HashMode { SHA256_MODE, AC_MODE };

struct Block {
    int index;
    string data;
    string previousHash;
    string hash;
    int nonce;
    HashMode mode;

    string calculateHash() const {
        string blockData = to_string(index) + previousHash + data + to_string(nonce);
        if (mode == AC_MODE)
            return ac_hash(blockData, 110, 8);
        else
            return SimpleSHA256::sha256(blockData);
    }
};

string mineBlock(Block& block, int difficulty, int& iterations) {
    string target(difficulty, '0');
    iterations = 0;
    const int maxIter = 10000;
    do {
        block.nonce++;
        block.hash = block.calculateHash();
        iterations++;
        if (iterations >= maxIter) break;
    } while (block.hash.substr(0, difficulty) != target);
    cout << "Bloc mine : " << block.hash.substr(0,16) << "..." << endl;
    return block.hash;
}

bool isChainValid(const vector<Block>& chain) {
    for (size_t i=1; i<chain.size(); ++i) {
        if (chain[i].previousHash != chain[i-1].hash) {
            cout << "Lien casse entre blocs !" << endl;
            return false;
        }
    }
    cout << "Chaine valide " << endl;
    return true;
}

//////////////////////////////////////
// Partie 4.2 : Comparaison
//////////////////////////////////////

void compare_hash() {
    cout << "\n===== COMPARAISON AC_HASH vs SHA256 =====\n";
    cout << "Bloc\t AC_HASH(ms)\t Iter\t SHA256(ms)\t Iter\n";

    int numBlocks = 10;
    int difficulty = 4;
    for (int i = 1; i <= numBlocks; ++i) {
        Block ac{ i, "Data AC", "0", "", 0, AC_MODE };
        Block sha{ i, "Data SHA", "0", "", 0, SHA256_MODE };

        int iterAC, iterSHA;

        auto start = high_resolution_clock::now();
        mineBlock(ac, difficulty, iterAC);
        auto end = high_resolution_clock::now();
        auto durationAC = duration_cast<milliseconds>(end - start).count();

        start = high_resolution_clock::now();
        mineBlock(sha, difficulty, iterSHA);
        end = high_resolution_clock::now();
        auto durationSHA = duration_cast<milliseconds>(end - start).count();

        cout << i << "\t" << durationAC << "\t\t" << iterAC
             << "\t" << durationSHA << "\t\t" << iterSHA << endl;
    }
}

///////////////////// Partie 5 ///////////////////////

std::bitset<256> binary_string_to_bitset(const std::string& bin_str) {
    if (bin_str.size() != 256) {
        // Optionnel : étendre ou tronquer
        std::string fixed = bin_str;
        if (fixed.size() < 256) {
            fixed = std::string(256 - fixed.size(), '0') + fixed; // padding à gauche
        } else if (fixed.size() > 256) {
            fixed = fixed.substr(0, 256);
        }
        return std::bitset<256>(fixed);
    }
    return std::bitset<256>(bin_str);
}

// Fonction pour compter les bits différents entre deux bitsets
int hamming_distance(const std::bitset<256>& a, const std::bitset<256>& b) {
    return (a ^ b).count();
}

// Fonction de test pour l'effet avalanche
void test_avalanche_effect(uint32_t rule = 30, size_t steps = 256, int num_tests = 100) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    double total_diff_percent = 0.0;

    for (int t = 0; t < num_tests; ++t) {
        // Générer un message aléatoire de 32 octets (256 bits)
        std::string msg1;
        for (int i = 0; i < 32; ++i) {
            msg1 += static_cast<char>(dis(gen));
        }

        // Copier et modifier un bit aléatoire
        std::string msg2 = msg1;
        size_t bit_to_flip = gen() % (32 * 8); // 256 bits
        size_t byte_index = bit_to_flip / 8;
        size_t bit_index = bit_to_flip % 8;
        msg2[byte_index] ^= (1 << bit_index);

        // Hacher les deux messages → retourne une chaîne de '0'/'1' de 256 caractères
        std::string hash1_bin = ac_hash(msg1, rule, steps);
        std::string hash2_bin = ac_hash(msg2, rule, steps);

        // Convertir en bitset
        std::bitset<256> hash1_bits = binary_string_to_bitset(hash1_bin);
        std::bitset<256> hash2_bits = binary_string_to_bitset(hash2_bin);

        int diff_bits = hamming_distance(hash1_bits, hash2_bits);
        double percent = (diff_bits * 100.0) / 256.0;
        total_diff_percent += percent;
    }

    double avg_percent = total_diff_percent / num_tests;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Effet avalanche moyen (" << num_tests << " tests, Rule " << rule << "): "
              << avg_percent << "% de bits differents\n";
}


////////////////// Partie 6 ///////////////////////////

void test_bit_distribution(uint32_t rule = 30, size_t steps = 256, size_t min_bits = 100000) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    size_t total_bits = 0;
    size_t total_ones = 0;
    size_t hashes_needed = (min_bits + 255) / 256; // arrondi supérieur

    for (size_t i = 0; i < hashes_needed; ++i) {
        // Générer un message aléatoire de 32 octets
        std::string msg;
        for (int j = 0; j < 32; ++j) {
            msg += static_cast<char>(dis(gen));
        }

        // Hacher
        std::string hash_bin = ac_hash(msg, rule, steps);

        // Compter les '1'
        for (char c : hash_bin) {
            if (c == '1') total_ones++;
            total_bits++;
        }
    }

    double ratio = (total_ones * 100.0) / total_bits;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Distribution des bits (Rule " << rule << ", " << total_bits << " bits): "
              << ratio << "% de bits a 1 ";
    if (std::abs(ratio - 50.0) <= 2.0) {
        std::cout << " Equilibree \n";
    } else {
        std::cout << " Desequilibree \n";
    }
}

/////////////////// Partie 7 //////////////////////////
#include <chrono>

void test_rule_performance_and_stability() {
    std::vector<uint32_t> rules = {30, 90, 110};
    size_t steps = 256;
    int num_runs = 100; // pour la moyenne de temps
    std::string test_input = "Blockchain test input for performance evaluation";

    cout << "\n===== TEST partie 7 : Performance et stabilite =====" << endl;
    cout << "Règle | Temps moyen (µs) | Hash exemple (32 premiers bits) | Stable?\n";
    cout << "---------------------------------------------------------------\n";

    for (uint32_t rule : rules) {
        // --- Mesure de temps ---
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < num_runs; ++i) {
            ac_hash(test_input, rule, steps);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double avg_time = static_cast<double>(duration.count()) / num_runs;

        // --- Vérification de stabilité (déterminisme) ---
        string hash1 = ac_hash(test_input, rule, steps);
        string hash2 = ac_hash(test_input, rule, steps);
        bool stable = (hash1 == hash2);

        // --- Affichage ---
        cout << rule << "   | " 
             << std::fixed << std::setprecision(2) << avg_time << "          | "
             << hash1.substr(0, 32) << "... | "
             << (stable ? "Oui" : "Non") << "\n";
    }

  
}
////////////////////////Programme principal//////////////////////////
int main() {
   string bits = "000010000";
    int rule = 110;
    int steps = 15;

    vector<int> state = init_state(bits);
    cout << "Etat initial : " << bits << endl;
    for (int i = 0; i < steps; ++i) {
        affichage(state);
        state = evolve(state, rule);
    }

    string h1 = ac_hash("Blockchain", 110, 1000);
    string h2 = ac_hash("Blockchaine", 110, 1000);

    cout << "Hash1 : " << h1.substr(0,32) << "..." << endl;
    cout << "Hash2 : " << h2.substr(0,32) << "..." << endl;
    if (h1 != h2) cout << "Les deux entrees produisent des hash differents !" << endl;
    else cout << "Les hash sont identiques (erreur)" << endl;

    cout << "\n===== TEST BLOCKCHAIN RAPIDE =====" << endl;
    vector<Block> blockchain;
    int difficulty = 4;
    HashMode mode = SHA256_MODE;

    Block genesis{0,"Bloc Genesis","0","",0,mode};
    int iter;
    mineBlock(genesis,difficulty, iter);
    blockchain.push_back(genesis);

    Block b1{1,"Transaction A -> B",genesis.hash,"",0,mode};
    mineBlock(b1,difficulty, iter);
    blockchain.push_back(b1);

    Block b2{2,"Transaction B -> C",b1.hash,"",0,mode};
    mineBlock(b2,difficulty, iter);
    blockchain.push_back(b2);

    isChainValid(blockchain);

    compare_hash();

    //// test partie 5
    cout << "\n===== TEST partie 5 =====" << endl;
    test_avalanche_effect(30, 256, 100);  // Rule 30
    test_avalanche_effect(90, 256, 100);  // Rule 90
    test_avalanche_effect(110, 256, 100); // Rule 110

    /// test partie 6 //
    cout << "\n===== TEST partie 6 =====" << endl;
    test_bit_distribution(30, 256, 100000);
    test_bit_distribution(90, 256, 100000);
    test_bit_distribution(110, 256, 100000);

    // test partie 7 //
    cout << "\n";
    test_rule_performance_and_stability();
    return 0;
}
