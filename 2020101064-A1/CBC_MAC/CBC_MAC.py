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

