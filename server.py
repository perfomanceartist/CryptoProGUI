import pycades
import socket

import myasn1

class Server:
    def __init__(self, ip : str = "127.0.0.1", port : int = 9000):
        with open("password.txt", "r") as f:
            self.password = f.readline()
        store = pycades.Store()
        store.Open(pycades.CADESCOM_CONTAINER_STORE, pycades.CAPICOM_MY_STORE, pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
        self.certs = store.Certificates
        assert(self.certs.Count != 0), "Certificates with private key not found"

        self.socket = socket.socket()
        self.socket.bind((ip, port))

        print(f"Listening on {ip}:{port}")
        self.socket.listen(1)
        self.conn, address = self.socket.accept()
        print("Connection from: " + str(address))
        self.Listening()


    def Listening(self):
        data = self.conn.recv(4096)
        if not data:
            self.socket.close()
            exit(0)

        responce = "[+] Message verified"  
        myasn = myasn1.MyAsn()

        encrypted, signature, encryptedFlag = myasn.decode(data)
        print(encrypted, signature, encryptedFlag)
        if encryptedFlag:
            encryptedData = pycades.EncryptedData()
            encryptedData.SetSecret = self.password
            encryptedData.Decrypt(encrypted)
            content = encryptedData.Content

            print("Сообщение было зашифровано.")
            print(f"Текст расшифрованного сообщения: \n{content}\n")
        else:
            print("Сообщение не было зашифровано.")
            print(f"Текст сообщения: \n{encrypted}")

        if signature != '-':
            print(f"Сообщение содержит подпись.")
            _signedData = pycades.SignedData()
            try:
                _signedData.VerifyCades(signature, pycades.CADESCOM_CADES_BES)
                print("Подпись верна!")
            except:
                responce = "[-] Signature verifying failed"
                print("Проверка завершилась неудачно.")  
        else:
            print("Подпись в сообщении отсутствует.")
        self.conn.send(responce.encode())
        self.socket.close()
        exit(0)


    def DecryptMessage(self, hash_value, message):

        # print(f"\n\nHASH VALUE:----\n{hash_value}----\n")
        # print(f"\n\nMESSAGE:----\n{message}----\n")

        _envelopedData = pycades.EnvelopedData()
        _envelopedData.Decrypt(message)

        hashedData = pycades.HashedData()
        hashedData.Algorithm = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411
        hashedData.Hash(_envelopedData.Content)

        if hashedData.Value == hash_value:
            responce = "[+] Verification succeeded."
        else:
            responce = "[-] Verification failed!"

        return responce



    def CheckHash(self, data, hash_value):
        hashedData = pycades.HashedData()
        hashedData.Algorithm = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411
        hashedData.Hash(data)

        if hashedData.Value == hash_value:
            responce = "[+] Verification succeeded."
        else:
            responce = "[-] Verification failed!"

        return responce


    def CheckSignature(self, hash_value, signature):
        responce = "[+] Verification succeeded."

        _hashedData = pycades.HashedData()
        _hashedData.Algorithm = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 
        _hashedData.SetHashValue(hash_value)

        _signedData = pycades.SignedData()
        try:
            _signedData.VerifyHash(_hashedData, signature, pycades.CADESCOM_CADES_BES)
        except:
            responce = "[-] Verification failed!"

        return responce






def main():
    serv = Server()

if __name__ == "__main__":
    main()
