"""
Implementation of Generic CPA Decryption Attack on Ascon-128 in Nonce-Misuse Setting by Exploiting XOR Patterns
paper link: https://ieeexplore.ieee.org/document/10566378
Patterns are extracted from XOR operation between the rate and chosen-plaintext bytes
Requirements: encryption oracle - nonce misuse setting
Mohamed Tarek: motarek@ieee.org
"""
from encryption_oracle import ascon_encrypt
query = 0 # track number of required queries for the attack (directly related to number of ciphertext bytes)

# prefix is added to specify the exact order of the rate byte to extract patterns from
def extract_XOR_patterns(prefix, associateddata, variant="Ascon-128") -> tuple:
    global query
    global ct0

    # send 5 chosen-plaintxt queries
    pt = [b'\x00', b'\x01', b'\x02', b'\x03', b'\x04'] # chosen-plaintext
    ct = []
    for p in pt:
        ct.append(ascon_encrypt(associateddata, prefix+p, variant)[len(prefix):-16].hex())
        query += 1
    ct0 = ct[0]

    # extract XOR patterns of the rate
    sequential_pattern = 1 if ct[0] < ct[1] else -1
    transision_pattern = 0 # transisiton patterns are deviations from the sequential pattern
    transition_frequency = 0 # how often does transition_pattern occurs?

    counter = 1
    for c in range(1, len(ct)):
        if ct[c] != hex_add('0x'+ct[c-1], sequential_pattern).replace('0x',''): # detect transition patterns
            if (int(ct[c], 16) - int(ct[c-1], 16)) > 1:
                transision_pattern = int(ct[c], 16) - int(ct[c-counter], 16)
            elif (int(ct[c], 16) - int(ct[c-1], 16)) < 1:
                transision_pattern = -c
            else:
                transision_pattern = 0

            transition_frequency = c
            break
        else: counter += 1

    # detecting double transision_pattern: (+2, -6) or (-2, +6)
    if abs(transision_pattern) == 2:
        for c in range(3, len(ct)):
            if ct[c] != hex_add('0x'+ct[c-1], sequential_pattern).replace('0x',''):
                transision_pattern = (transision_pattern, int(ct[c], 16) - int(ct[c-2], 16))
                break
    return sequential_pattern, transision_pattern, transition_frequency

# build a lookup table to map all possible hexadecimal bytes to their corresponding ciphertext bytes
def create_predicted_ciphertext_table(prefix, XOR_patterns: tuple, associateddata, variant="Ascon-128") -> list:
    global query

    # XOR patterns
    sequential_pattern = XOR_patterns[0]
    transision_pattern = XOR_patterns[1]
    transition_frequency = XOR_patterns[2]

    # finding results of XORing with starting points
    hex_bytes = [b.to_bytes(1, 'big') for b in range(0x10, 0x100, 0x10)] # 15 queries for 15 starting points
    hex_sp = [ct0] # first starting point was already extracted from encrypting '\x00' in the previous step
    for byte in hex_bytes:
        hex_sp.append(ascon_encrypt(associateddata, prefix+byte, variant)[len(prefix):-16].hex()) # sp = starting point
        query += 1

    # build predicted_ciphertext_table by predicting the results of XOR operation using extracted XOR patterns
    predicted_ciphertext_table = []
    counter = 0

    for sp in hex_sp:
        if type(transision_pattern) == tuple:
            flag = 0
        sp = int(sp, 16)
        predicted_ciphertext_table.append(hex_pad(hex(sp), 2))
        ct = sp
        i = 1
        counter+=1
        while i < 16:
            if transition_frequency == 0: # there is no transition pattern
                ct = int(hex_add(hex_pad(hex(ct), 2), sequential_pattern), 16)
                predicted_ciphertext_table.append(hex_pad(hex(ct), 2))
                i+=1
                counter+=1
            else: # there is a transition pattern
                for j in range(1, transition_frequency):
                    ct = int(hex_add(hex_pad(hex(ct), 2), sequential_pattern), 16) # apply sequential pattern
                    predicted_ciphertext_table.append(hex_pad(hex(ct), 2))
                    i+=1
                    counter+=1
                if i >= 16: break
                pointer = predicted_ciphertext_table[counter-(transition_frequency * abs(sequential_pattern))] 

                if type(transision_pattern) == tuple: # apply transition pattern
                    ct = int(hex_add(hex_pad(pointer, 2), transision_pattern[flag]), 16) 
                    flag = 1 if flag == 0 else 0
                else:
                    ct = int(hex_add(hex_pad(pointer, 2), transision_pattern), 16)
                
                predicted_ciphertext_table.append(hex_pad(hex(ct), 2))
                i+=1
                counter+=1
    return predicted_ciphertext_table

# decrypt a ciphertext byte
def decrypt_byte(ct_byte, predicted_ciphertext_table: list):
    ct_byte = hex_pad(hex(ct_byte), 2)
    plaintext = predicted_ciphertext_table.index(ct_byte).to_bytes(1, 'big')
    return plaintext

#___ HELPER FUNCTIONS ___# 
def hex_pad(a, b):
    while len(a.replace('0x','')) < b:
        a = '0x0'+a.replace('0x','')
    return a

def hex_add(num, add):
    hexnum = [i for i in range(16)]
    sum = hex_pad(hex(hexnum[(int(num, 16) + add)%16]), 2)
    sum = sum[:2] + num[2] + sum[3]
    return sum

#___ MAIN ___#
def cpa_pattern_attack(associateddata, ciphertext, variant="Ascon-128") -> tuple:
    ciphertext = ciphertext[:-16]
    decrypted = b"" 

    for byte in range(len(ciphertext)): # for each byte in ciphertext
        XOR_patterns = extract_XOR_patterns(decrypted, associateddata, variant)
        predicted_ciphertext_table = create_predicted_ciphertext_table(decrypted, XOR_patterns, associateddata, variant)
        decrypted += decrypt_byte(ciphertext[byte], predicted_ciphertext_table)
    return decrypted, query

#___ TEST ___# ~ we can use NIST test vectors
associateddata = b""
ciphertext = bytes.fromhex('3ade0b468ccf899f45bf4f40ffd8555fbcce79672dd14f83')
decrypted = cpa_pattern_attack(associateddata, ciphertext)
print(f"decrypted message: {decrypted[0]}\nnumber of required queries: {decrypted[1]}")
