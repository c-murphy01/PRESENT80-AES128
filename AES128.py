
######################
# CONSTANTS
######################

#substitution box used to substitute bytes each round to add confusion
sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

#round constants used to generate different keys each round
rcon = [0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 
        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]

#matrix for mix columns step
mix_columns_matrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

######################
# HELPER FUNCS
######################

#func to take plaintext input and covert to byte array for manipulation
def plaintext_to_matrix(plaintext):
    #create a byte array from the plaintext hexadecimal string
    byte_array = bytes.fromhex(plaintext)
    
    #create a 4x4 matrix and fill it with zeros
    state = []
    for i in range(4):
        row = []
        for j in range(4):
            row.append(0)
        state.append(row)
    
    #fill the matrix with values from the byte array
    for col in range(4):
        for row in range(4):
            #must be filled column by column for AES
            state[row][col] = byte_array[row + 4*col]
            
    return state

def matrix_to_plaintext(matrix):
    #create empty string to store ciphertext
    plaintext = ''
    
    #iterate through bytes column by column
    for col in range(4):
        for row in range(4):
            byte = matrix[row][col]
            #convert to hexadecimal, using leading zeros up to 2 characters
            hex_str = format(byte, '02x')
            #add to ciphertext
            plaintext += hex_str
    return plaintext

#function to carry out Galois Field multiplication, takes 2 8 bit (1 byte) inputs
def galois_multiplication(byte1, byte2):
    result = 0
    #iterate 8 times, 1 per bit in a byte
    for counter in range(8):
        #for each iteration, check if LSB of byte 2 is 1, if so XOR current byte 1 with result
        if byte2 & 1: result ^= byte1
        #check if byte 1 MSB is 1
        hi_bit = byte1 & 0x80
        #shift left by 1 bit
        byte1 <<= 1
        #if MSB is 1, modulo with x^4 + x^3 + x + 1.
        if hi_bit:
            byte1 ^= 0x1B
        #shift byte 2 right and repeat
        byte2 >>= 1
    return result & 0xFF #ensure result fits in 8 bits

######################
# MAIN ROUND FUNCS
######################

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            #bitwise right shift by 4 bits to only keep the 4 MSB to find sbox row
            row = state[i][j] >> 4
            #bitwise AND which hides 4 MSB and leaves only 4 LSB to find sbox column
            col = state[i][j] & 0x0F
            #substitute byte using sbox (*16 shifts row bits left by 4)
            state[i][j] = sbox[row * 16 + col]
    return state

def shift_rows(state):
    for i in range(1, 4):  #first row doesnt shift so start loop from 1 (second row)
        state[i] = state[i][i:] + state[i][:i]
    return state  

def mix_columns(state):
    #create a state array filled with zeros
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(4): #loop through columns 
        for j in range(4): #loop through rows
            #for each element of the new state, perform galois multiplication betweeen the corresponding element of the mix_columns_matrix
            #and the current state matrix, and XOR the results. This gives the equivalent of multiplying both matrices column wise
            new_state[j][i] = (
                galois_multiplication(mix_columns_matrix[j][0], state[0][i]) ^
                galois_multiplication(mix_columns_matrix[j][1], state[1][i]) ^
                galois_multiplication(mix_columns_matrix[j][2], state[2][i]) ^
                galois_multiplication(mix_columns_matrix[j][3], state[3][i])
            )
            
    #return the new state with mixed columns
    return new_state

#func to add round key to state
def add_round_key(state, round_key):
    for col in range(4):
        for row in range(4):
            #XOR addition of round key to state
            state[row][col] ^= round_key[row][col]
    return state


######################
# KEY EXPANSION FUNCS
######################

def rot_word(word):
    return word[1:] + word[:1] #rotate word by one byte

def sub_word(word):
    return [sbox[byte] for byte in word] #use sbox to substitute each byte in word

def key_expansion(key):
    key_matrix = plaintext_to_matrix(key)
    
    round_key_columns = []
    for col in range(4):
        #create empty column
        column = []
        for row in range(4):
            #add value to column
            column.append(key_matrix[row][col])
        #add full column to round key columns
        round_key_columns.append(column)

    for i in range(4, 44):  #11 round keys = 44 words
        temp = round_key_columns[i - 1].copy() #copy the last word
        if i % 4 == 0:
            #for every 4th word, do the following
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= rcon[i // 4] >> 24  #XOR on firszt byte of temp and MSByte of round constant (which rcon depends on the round)

        new_column = []
        for j in range(4):
            new_column.append(temp[j] ^ round_key_columns[i - 4][j]) #XOR temp with the word 4 words back and add to round key columns
        round_key_columns.append(new_column)

    #every 4 columns makes a round key
    round_keys = []
    for i in range(0, 44, 4):
        round_key = round_key_columns[i:i + 4]
        #have to transpose round key to match AES standards
        transposed_round_key = []
        for row in range(4):
            new_row = []
            for col in range(4):
                new_row.append(round_key[col][row])  #swap rows with columns
            transposed_round_key.append(new_row)
        
        round_keys.append(transposed_round_key)

    return round_keys


def print_state(state, step):
    print(f"{step}:")
    for row in state:
        print(" ".join(format(x, '02x') for x in row))
    print()

######################
# MAIN FUNC
######################

def aes_encrypt(plaintext, key):
    state = plaintext_to_matrix(plaintext) #generate state matrix
    round_keys = key_expansion(key) #generate round keys

    add_round_key(state, round_keys[0]) #key whitening
    
    for i in range(1, 10):  #9 main rounds
        sub_bytes(state)
        shift_rows(state)
        state = mix_columns(state)
        add_round_key(state, round_keys[i]) #add round key at end of each round
    
    #last round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[-1]) #key whitening
    
    return matrix_to_plaintext(state) #return ciphertext in original format

######################
# USAGE
######################

plaintext = '0123456789abcdeffedcba9876543210'
key = '0f1571c947d9e8590cb7add6af7f6798'

print('Plaintext:  ' + '"' + plaintext + '"\n')
print('Key:        ' + '"' + key + '"\n')

ciphertext = aes_encrypt(plaintext, key)
print('Ciphertext: '+ '"'  + ciphertext + '"\n')
