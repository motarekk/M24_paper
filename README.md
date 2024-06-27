# Implementation of my paper: Generic CPA Decryption Attack on Ascon-128 in Nonce-Misuse Setting by Exploiting XOR Patterns
https://ieeexplore.ieee.org/document/10566378

#### -  The attack takes advantage of patterns extracted from the Bitwise XOR operation.
#### - It can be applied to any other cipher that includes an XOR operation at the final phase.
#### - The attack requires an encryption oracle and a nonce-misuse setting.
#### - The extracted XOR patterns could be used for other cryptographic applications such as key-exchange and zero-knowledge proofs (ZNPs). This is left for future work.

## Flow of attack steps 
<img width="569" alt="flow" src="https://github.com/motarekk/M24_paper/assets/104282801/c153e976-d06a-4a53-82de-2c17ef1ebc4c">

## You can also take a look at playascon (my online tool for Ascon cipher):
https://motarekk.github.io/
