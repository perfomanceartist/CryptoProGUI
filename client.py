import pycades
import socket



class Client:
    def __init__(self):
        store = pycades.Store()
        store.Open(pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_MY_STORE, pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
        self.certs = store.Certificates
        assert(self.certs.Count != 0), "Certificates with private key not found"

    def getCertificatesNames(self):
        namelist = []
        for i in range(1, self.certs.Count + 1):
            namelist.append(self.certs.Item(i).GetInfo(pycades.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME))
        #print()
        return namelist

    def Connect(self, ip: str = "127.0.0.1", port : int = 9000):
        try:
            self.socket = socket.socket()
            self.socket.connect((ip, port))
        except:
            return False
        return True

    def SendData(self, data:bytes):
        self.socket.send(data)
        answer = self.socket.recv(1024).decode()
        return f"Server responce: {answer}"

    def SignData(self, data : str, cert : int = 1, password=None) -> str:
        "Возвращает подпись"
        signer = pycades.Signer()
        signer.Certificate = self.certs.Item(cert)
        if password:
            signer.KeyPin = password
        signer.CheckCertificate = True        

        signedData = pycades.SignedData()
        signature = signedData.SignHash(data, signer, pycades.CADESCOM_CADES_BES) # :str
        
        print("\n--Signature--")
        print(signature)
        print("----\n\n\n\n")

        return signature

    def HashData(self, data : str, alg = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411) -> str:
        "Возвращает хеш"
        hashedData = pycades.HashedData()
        hashedData.Algorithm = alg
        hashedData.Hash(data)
        print("\n--Hash-")
        print(hashedData.Value) # :str
        print("----\n")
        return hashedData

    def EncryptData(self, data : str, cert : int = 1) -> str:
        "Возвращает зашифрованное сообщение"
        cert = self.certs.Item(cert)
        envelopedData = pycades.EnvelopedData()
        envelopedData.Content = data
        envelopedData.Recipients.Add(cert)

        encryptedMessage = envelopedData.Encrypt(pycades.CADESCOM_ENCODE_BASE64)

        print("--Encrypted Message--")
        print(encryptedMessage) # :str
        print("----")

        return encryptedMessage


