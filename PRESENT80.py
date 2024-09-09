
######################
# CONSTANTS
######################

#substitution box
sbox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

#permutation box
pbox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
         4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
         8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
         12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

#key schedule
def key_expansion(key):

    #convert hexadecimal string to integers
    if isinstance(key, str):
        key = int(key, 16)

    round_keys = []

    for i in range(1, 33): #32 round keys needed
        #shift right by 16 bits to extract the 64 leftmost bits
        #AND with 64bit mask to ensure it is 64 bits long
        round_key = (key >> 16) & 0xFFFFFFFFFFFFFFFF
        #append to key list
        round_keys.append(round_key)

        #rotate the key by 61 bits
        #shift left by 61, OR that with the key shifted right by 19 to rotate it
        #AND to ensiure 80 bit length
        key = ((key << 61) | (key >> 19)) & ((1 << 80) - 1)

        #extract leftmost 4 bits by shifting right by 76 bits, AND with mask to ensure 4bit length
        leftmost_4_bits = (key >> 76) & 0xF
        #apply sbox substitution
        sbox_output = sbox[leftmost_4_bits]
        #update the key with subbed values
        key = (sbox_output << 76) | (key & ((1 << 76) - 1))
        
        #XOR round counter with bits 15-19 of key
        #AND with 0x1F to ensure 5 bit length
        key ^= (i & 0x1F) << 15
    
    return round_keys

######################
# HELPER FUNCS
######################

def substitue(state, sbox):
    new_state = 0
    #16 4 bit nibbles
    for i in range(16):
        #extract nibble by shifting right and masking the rest to isolate that nibble
        nibble = (state >> (i * 4)) & 0xF
        #substitute using sbox and shift back to correct position
        new_state |= sbox[nibble] << (i * 4)
    return new_state

def permutate(state, pbox):
    new_state = 0
    #iterate through each bit
    for i in range(64):
        #change bit to be moved
        bit = (state >> i) & 1
        #move bit according to pbox
        new_state |= bit << pbox[i]
    return new_state

######################
# MAIN ALGORITHM
######################
def present_encrypt(plaintext, key):
    
    #convert key plaintext and key to integers
    plaintext = int(plaintext, 16)
    key = int(key, 16)

    #generate round keys
    round_keys = key_expansion(key)

    #create initial state
    state = plaintext
    #31 rounds of the regular algorithm
    for i in range(31):
        #add round key
        state ^= round_keys[i]
        #substitue
        state = substitue(state, sbox)
        #permutate   
        state = permutate(state, pbox)
    
    #add final round key
    state ^= round_keys[31]

    #return the final state as a hexadecimal string
    return format(state, '016x')

######################
# USAGE
######################

plaintext = '0000000000000000'
key = '10000000000000000000'

print('Plaintext:  ' + '"' + plaintext + '"\n')
print('Key:        ' + '"' + key + '"\n')

ciphertext = present_encrypt(plaintext, key)
print('Ciphertext:  ' + '"' + ciphertext + '"\n')
