class CryptoFormat:
    def __init__(self):
        self.dict = {}

    def add_data(self, key, value):
        if isinstance(value, str):
            parts = [value[i:i+60] for i in range(0, len(value), 60)]
            parts = ['    ' + x for x in parts]
        else:
            parts = ['    ' + x for x in value]

        self.dict[key + ':'] = parts

    def output_data(self, filename):
        with open(filename, 'w') as file:
            file.write('---BEGIN OS2 CRYPTO DATA---\n')
            for key, value in self.dict.items():
                file.write(key + '\n')
                for v in value:
                    file.write(v + '\n')
                file.write('\n')

            file.write('---END OS2 CRYPTO DATA---')
