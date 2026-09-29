# Advanced Encryption Standard - AES
Documentation - from [NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)

The basic processing unit in the AES algorithms is the byte — a sequence of eight bits. \
A word is a sequence of four bytes. \
The general function for executing AES-128, AES-192, or AES-256 is denoted by CIPHER().

## **The State**
AES block cipher algorithms in Section 5, the frst step is to copy the
input array of bytes in0, in1, ..., in15 to the state array s.
An individual byte of the state is denoted by either s[r, c] and each will be of size = 1byte, since input block is always 128 bits (8 bits x 16)


## **Round**
The core of the algorithms for CIPHER() and INVCIPHER() is a sequence of fixed transformations
of the state called a round. Each round requires an additional input called the round key; the round
key is a block that is usually represented as a sequence of four words (i.e., 16 bytes). 

## **KeyExpansion**
*   An expansion routine, denoted by *KEYEXPANSION()*, takes the block cipher key as input and
generates the round keys as output. In particular, the input to KEYEXPANSION() is represented as
an array of words, denoted by key, and the output is an expanded array of words, denoted by **w**,
called the key schedule. 
*   KEYEXPANSION() invokes 10 fxed words denoted by Rcon[ j] for 1 ≤ j ≤ 10. These 10 words
are called the round constants






The block ciphers AES-128, AES-192, and AES-256 differ in three respects: 
1) the length of the key (Nk - Number of words)
2) the number of rounds (Nr), which determines the size of the required key schedule
3) the specifcation of the recursion within KEYEXPANSION().

                AES-...(in,key) = CIPHER(in,Nr,KEYEXPANSION(key))   where ... = 128 or 192 or 256 and Nk be 10, 12, 14 respectively.
              
## **Steps**
1. state ← in
2. state ← ADDROUNDKEY(state,w[0..3])  - combines a round key with the state. 
3. for round from 1 to Nr −1 do
        3a. state ← SUBBYTES(state)
        3b. state ← SHIFTROWS(state)
        3c. state ← MIXCOLUMNS(state)
        3d. state ← ADDROUNDKEY(state,w[4 ∗ round..4 ∗ round +3])
   end for
4. state ← SUBBYTES(state)
5. state ← SHIFTROWS(state)
6. state ← ADDROUNDKEY(state,w[4 ∗Nr..4 ∗Nr +3])


*Note:* 
i. ADDROUNDKEY() is a transformation of the state in which a round key is combined with the
state by applying the bitwise XOR operation \
ii. Only aes_core.v is sequential circuit out of all modules written.



