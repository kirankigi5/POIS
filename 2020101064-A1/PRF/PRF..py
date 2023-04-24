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
