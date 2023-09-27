import asn1


class MyAsn():
    def __init__(self) -> None:
        self.encoder = asn1.Encoder()
        self.decoder = asn1.Decoder()
        

    def encode(self, b64encryptedstr='-', b64signment='-', encryptedFlag = True):
        self.encoder.start()
        self.encoder.enter(asn1.Numbers.Sequence) # Main Sequence
        
        self.encoder.write(encryptedFlag, asn1.Numbers.Boolean)

        self.encoder.enter(asn1.Numbers.Sequence) # Encrypted text Sequence
        self.encoder.write(b64encryptedstr, asn1.Numbers.PrintableString)
        self.encoder.leave()

        self.encoder.enter(asn1.Numbers.Sequence) # Signment Sequence
        self.encoder.write(b64signment, asn1.Numbers.PrintableString)
        self.encoder.leave()

        self.encoder.leave()

        return self.encoder.output() # bytes


    def decode(self, encoded:bytes):        
        self.decoder.start(encoded)
        self.decoder.enter()

        _, encryptedFlag = self.decoder.read()

        self.decoder.enter()        
        _, encrypted = self.decoder.read()
        self.decoder.leave()

        self.decoder.enter()        
        _, signment = self.decoder.read()
        self.decoder.leave()

        self.decoder.leave()

        return encrypted, signment, encryptedFlag #strings, bool


if __name__ == "__main__":
    myasn = MyAsn()

    test1 = myasn.encode().decode()
    test2 = myasn.encode(b64encryptedstr='encryptedtext').decode()
    test3 = myasn.encode(b64signment='signment').decode()
    test4 = myasn.encode(b64encryptedstr='enc', b64signment='sign')


    enc, sign = myasn.decode(test4)

    print(enc, sign)
