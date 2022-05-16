from email.mime import message
from cryptosteganography import CryptoSteganography
from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)


def splitCheck(ciphersplit):
    leng = len(ciphersplit) // 4
    st = ''
    for i in range(0,len(ciphersplit)):
        if i % leng == 0 and i != 0:
            st += '-'
        st += ciphersplit[i]
    neww = st.split('-')
    
    arr = []
    if len(neww) > 4:
        for i in range(0, 3):
            arr.append(neww[i])
        arr.append(neww[3] + neww[4])
        return arr

    else:
        return neww


class process:
    nonce = 0
    tag = 0
    ciphertext = 0
    def __init__(self, msg): 
        self.msg = msg;

    def doencrpt(self):
        cipher = AES.new(key, AES.MODE_EAX)
        self.nonce = cipher.nonce
        self.ciphertext, self.tag = cipher.encrypt_and_digest(self.msg.encode('ascii'))
        print("Cipher text: ", self.ciphertext)
        # return nonce, ciphertext, tag

    def steg(self):
        crypto_steganography = CryptoSteganography('My secret password key')
        crypto_steganography.hide('img/input_image_name.jpg', 'img/output_image_file.png', self.ciphertext)
        self.secret = crypto_steganography.retrieve('img/output_image_file.png')
        

    def decrypt(self):
        cipher = AES.new(key, AES.MODE_EAX, nonce=self.nonce)
        plaintext = cipher.decrypt(self.secret)
        try:
            cipher.verify(self.tag)
            return plaintext.decode('ascii')
        except:
            return False

if __name__ == '__main__':
    Message = input("Enter a message: ")
    actual = splitCheck(Message)
    
    obj = process(Message)
    obj.doencrpt()
    obj.steg()
    print("Plain Text: ", obj.decrypt())


