import bson
import numpy as np


# RC4 Implementation
def rc4_ksa(key, n=256):
    """
    RC4 Key Scheduling Algorithm

    :param key: Key Bytes as list or bytestring
    :param n: Normally, the number of rounds is always 256, but many attacks modify it
    :return: Initialized S-Boxes, last value of j
    """
    S = list(range(256))
    j = 0
    for i in range(n):
        j = (j + S[i] + key[i % len(key)]) % 256
        tmp = S[i]
        S[i] = S[j]
        S[j] = tmp
    return S, j


def rc4_prga(S, count=8):
    """
    RC4 Pseudorandom Generator Algorithm

    :param S: Initialized S-Boxes from the KSA
    :param count: Number of bytes to produce
    :return: Output bytes to be XORed with the plaintext
    """
    i = 0
    j = 0
    output = []
    while len(output) < count:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        tmp = S[i]
        S[i] = S[j]
        S[j] = tmp
        output.append(S[(S[i] + S[j]) % 256])
    return output


# Validate implementation
def validate_rc4():
    """
    Use this method to verify your RC4 implementation.
    You can for example use the following values for testing:
    Key: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    Keystream: 0xde, 0x18, 0x89, 0x41, 0xa3, 0x37, 0x5d, 0x3a

    :return: True, if implementation seems to be valid
    """
    key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    S, _ = rc4_ksa(key)
    out = rc4_prga(S, 8)
    return out == [0xde, 0x18, 0x89, 0x41, 0xa3, 0x37, 0x5d, 0x3a]

def swap(arr,i,j):
    tmp = arr[i]
    arr[i] = arr[j]
    arr[j] = tmp

def get_key_with_highest_frequency(frequency):
    max_frequency = np.max(frequency)
    key = frequency.index(max_frequency)
    return key


def save_values_of_s_box(s_box, s_box_in_step_1, A):
    s_box_in_step_1[0] = s_box[0]
    s_box_in_step_1[1] = s_box[1]
    s_box_in_step_1[2] = s_box[A+3]


def get_index_of_s_for_z(s_box):
    i = 1
    j = s_box[i]
    index = s_box[i]+s_box[j]
    return index


def initialize_iv_in_key(key, packet):
    for i in range(3):
        key[i] = int(packet[24+i])  # packet[24:27] is IV

        
def fms_attack(packets):
    N = 256
    plain_llc = "aa"
    key_len = 13  # 104 bit key
   
    key = [0] * (key_len+3) # 3 byte iv & 13 byte key
    for A in range(key_len):
        frequency = [0] * N
        for packet in packets:
            
            s_box_in_step_1 = [0] * 3
            ciphered_llc = packet[28]
            

            initialize_iv_in_key(key, packet)

            if key[0]!=(A+3) or key[1]!=(N-1):
                continue

            s_box = list(range(N))

            j = 0
            # KSA in s_box for i = 0 -> A+3
            for i in range(A + 3):
                j = (j + s_box[i] + key[i]) % N
                swap(s_box, i, j)
                
                # after step 1 save values to check later
                if i == 1:
                    save_values_of_s_box(s_box, s_box_in_step_1, A)

            i = A + 3
            index_of_s_for_z = get_index_of_s_for_z(s_box)

            # if if s[0] and s[1] does not change after step 1
            # index_of_s_for_z == A + 3, from PRGA z[0] = S[S[i]+S[j]] = j'
            if s_box_in_step_1[0] == s_box[0] and s_box_in_step_1[1] == s_box[1] and index_of_s_for_z == A+3:
                z = ciphered_llc ^ int(plain_llc, 16)
                key_i = (z-j-s_box[i]) % N

                frequency[key_i] = frequency[key_i] + 1 #increment the frequency value for key_i

        key[A+3] = get_key_with_highest_frequency(frequency)

    secret_key = key[3:]
    print("secret key = ",secret_key)

    # directly save the key - hex
    with open("sample1.bin", "bw") as file:
        file.write(bytearray(secret_key))
    #file.close()

    secret_key_bin = map(lambda x: f'{x:0>8b}', secret_key)
    secret_key_str = ''.join(list(secret_key_bin))
    
    print("secret key binary = ",secret_key_str)
    
    new_string = bytearray(secret_key_str,"ascii")
    print("new string = ",new_string)

    with open("sample2.bin", "bw") as file:
        file.write(bytearray(secret_key_str,"ascii"))
    



def main():
    assert validate_rc4(), "RC4 Implemention is incorrect"
    
    # This loads the example packets we give you for local testing. 
    # Please be adviced that in the pipeline you need to read packets.bson !
    with open("example_packets.bson", "rb") as f:
        packets = bson.loads(f.read())["packets"]
    fms_attack(packets)
    
    # todo implement the FMS attack


if __name__ == '__main__':
    main()

