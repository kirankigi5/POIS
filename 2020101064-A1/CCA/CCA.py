from typing import Optional


class PRG:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, expansion_factor: int):
        """
        Initialize values here
        :param security_parameter: n (from 1ⁿ)
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param expansion_factor: l(n)
        :type expansion_factor: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.expansion_factor = expansion_factor

    def generate(self, seed: int) -> str:
        """
        Generate the pseudo-random bit-string from seed
        :param seed: uniformly sampled seed
        :type seed: int
        """
        output_string = ''
        y = seed  # y = g^x (mod p)

        for i in range(self.expansion_factor):

            curr_seed = y

            if(y < (self.prime_field - 1) / 2):
                output_string += '0'
            else:
                output_string += '1'

            y = (self.generator ** curr_seed) % self.prime_field

        return output_string


class PRF:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, key: int):
        """
        Initialize values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: p
        :type prime_field: int
        :param key: k, uniformly sampled key
        :type key: int
        """
        self.security_parameter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.key = key

    def evaluate(self, x: int) -> int:
        """
        Evaluate the pseudo-random function at `x`
        :param x: input for Fₖ
        :type x: int
        """
        x_bin = bin(x)[2:].zfill(self.security_parameter)

        PRG_seed = self.key

        PRG_instance = PRG(self.security_parameter, self.generator,
                           self.prime_field, 2 * (self.security_parameter))

        for i in range(self.security_parameter):
            PRG_output = PRG_instance.generate(PRG_seed)

            PRG_output_bin_1 = PRG_output[0: self.security_parameter]
            PRG_output_bin_2 = PRG_output[self.security_parameter:]

            if(x_bin[i] == '0'):
                output = PRG_output_bin_1
            else:
                output = PRG_output_bin_2

            PRG_seed = int(output, 2)

        return PRG_seed


class CBC_MAC:
    def __init__(self, security_parameter: int, generator: int,
                 prime_field: int, keys: list[int]):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param generator: g
        :type generator: int
        :param prime_field: q
        :type prime_field: int
        :param keys: k₁, k₂
        :type keys: list[int]
        """
        self.security_paremeter = security_parameter
        self.generator = generator
        self.prime_field = prime_field
        self.keys = keys

    def mac(self, message: str) -> int:
        """
        Message Authentication code for message
        :param message: message encoded as bit-string m
        :type message: str
        """
        n = self.security_paremeter
        init_tag = 0
        init_tag_bin = bin(init_tag)[2:].zfill(self.security_paremeter)

        d = int(len(message) / n)

        x = PRF(self.security_paremeter, self.generator,
                self.prime_field, self.keys[0])

        current_tag_bin = init_tag_bin

        for i in range(d):
            next_tag_bin = ''

            str1 = message[i * n: (i + 1) * n]

            str2 = current_tag_bin

            for i in range(self.security_paremeter):
                if(str1[i] == str2[i]):
                    next_tag_bin += '0'
                else:
                    next_tag_bin += '1'
            
            next_tag_bin = bin(x.evaluate(int(next_tag_bin, 2)))[2:].zfill(n)

            current_tag_bin = next_tag_bin

        x = PRF(self.security_paremeter, self.generator,
                self.prime_field, self.keys[1])

        final_num = x.evaluate(int(current_tag_bin,2))

        return final_num

    def vrfy(self, message: str, tag: int) -> bool:
        """
        Verify if the tag commits to the message
        :param message: m
        :type message: str
        :param tag: t
        :type tag: int
        """

        x = CBC_MAC(self.security_paremeter,self.generator, self.prime_field, self.keys)
        output_tag = x.mac(message)

        return tag==output_tag

class CPA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key: int, mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key: k
        :type key: int
        :param mode: Block-Cipher mode of operation
            - CTR
            - OFB
            - CBC
        :type mode: str
        """
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key = key
        self.mode = mode

    def enc(self, message: str, random_seed: int) -> str:
        """
        Encrypt message against Chosen Plaintext Attack using randomized ctr mode
        :param message: m
        :type message: int
        :param random_seed: ctr
        :type random_seed: int
        """
        x = PRF(self.security_parameter, self.generator,
                self.prime_field, self.key)

        cipher_text = ''

        num_blocks = int(len(message) / self.security_parameter)

        for i in range(1, num_blocks + 1):
            key_decimal = x.evaluate(random_seed + i)

            str_1 = bin(key_decimal)[2:].zfill(self.security_parameter)
            str_2 = message[(i - 1) * (self.security_parameter): (i * (self.security_parameter))]

            for i in range(len(str_1)):
                if(str_1[i] == str_2[i]):
                    cipher_text += '0'
                else:
                    cipher_text += '1'

        cipher_text = bin(random_seed)[2:].zfill(
            self.security_parameter) + cipher_text

        return cipher_text

    def dec(self, cipher: str) -> str:
        """
        Decrypt ciphertext to obtain plaintext message
        :param cipher: ciphertext c
        :type cipher: str
        """
        message = ''

        x = PRF(self.security_parameter, self.generator,
                self.prime_field, self.key)

        num_blocks = int((len(cipher) / self.security_parameter) - 1)

        random_seed = int(cipher[0: self.security_parameter], 2)

        for i in range(1, num_blocks + 1):
            key_decimal = x.evaluate(random_seed + i)

            str_1 = bin(key_decimal)[2:].zfill(self.security_parameter)
            str_2 = cipher[(i) * (self.security_parameter): (((i + 1)) * (self.security_parameter))]

            for i in range(len(str_1)):
                if(str_1[i] == str_2[i]):
                    message += '0'
                else:
                    message += '1'

        return message

class CCA:
    def __init__(self, security_parameter: int, prime_field: int,
                 generator: int, key_cpa: int, key_mac: list[int],
                 cpa_mode="CTR"):
        """
        Initialize the values here
        :param security_parameter: 1ⁿ
        :type security_parameter: int
        :param prime_field: q
        :type prime_field: int
        :param generator: g
        :type generator: int
        :param key_cpa: k1
        :type key_cpa: int
        :param key_mac: k2
        :type key_mac: list[int]
        :param cpa_mode: Block-Cipher mode of operation for CPA
            - CTR
            - OFB
            - CBC
        :type cpa_mode: str
        """
        # CCA = CPA(msg) + CBC_MAC(CPA(msg))
        self.security_parameter = security_parameter
        self.prime_field = prime_field
        self.generator = generator
        self.key_cpa = key_cpa
        self.key_mac = key_mac



    def enc(self, message: str, cpa_random_seed: int) -> str:
        """
        Encrypt message against Chosen Ciphertext Attack
        :param message: m
        :type message: str
        :param cpa_random_seed: random seed for CPA encryption
        :type cpa_random_seed: int
        """
        x = CPA(self.security_parameter, self.prime_field, self.generator, self.key_cpa)
        cpa_output_bin = x.enc(message, cpa_random_seed)

        y = CBC_MAC(self.security_parameter, self.generator, self.prime_field, self.key_mac)
        cbc_mac_output_bin = bin(y.mac(cpa_output_bin))[2:].zfill(self.security_parameter)

        output = cpa_output_bin + cbc_mac_output_bin

        return output

        
        

    def dec(self, cipher: str) -> Optional[str]:
        """
        Decrypt ciphertext to obtain message
        :param cipher: <c, t>
        :type cipher: str
        """
        tag = int(cipher[-self.security_parameter:], 2)
        cipher = cipher[:-self.security_parameter]

        self.cbc_mac = CBC_MAC(self.security_parameter, self.generator,self.prime_field, self.key_mac)
        self.cpa = CPA(self.security_parameter, self.prime_field, self.generator, self.key_cpa)

        if self.cbc_mac.vrfy(cipher, tag):
            return self.cpa.dec(cipher)
        else:
            return None
