
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
