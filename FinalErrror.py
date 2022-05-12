from email.mime import message
from cryptosteganography import CryptoSteganography
from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)

def steganographyCipher(ciphertextsteg, i):
    global secret
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide('input_image_name'+str(i)+'.jpg', 'output_image_file'+str(i)+'.png', ciphertextsteg)
    secret = crypto_steganography.retrieve('output_image_file'+str(i)+'.png')
    print(secret)
   

def steganographyNonce(ciphertextsteg):
    global Noncee
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide('nonce.jpg', 'nonce_output.png', ciphertextsteg)
    Noncee = crypto_steganography.retrieve('nonce_output.png')

def steganographyTag(ciphertextsteg):
    global Tagg
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide('tag.jpg', 'tag_output.png', ciphertextsteg)
    Tagg = crypto_steganography.retrieve('tag_output.png')

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

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


Message = input("Enter a message: ")
actual = splitCheck(Message)
print(actual)
for i in range(len(actual)):
    nonce, ciphertext, tag = encrypt(actual[i])
    steganographyCipher(ciphertext, i)
    # steganographyNonce(nonce)
    # steganographyTag(tag)
    plaintext = decrypt(nonce, secret, tag)
    print(f'Cipher text: {ciphertext}')
    if not plaintext:
        print('Message is corrupted')
    else:
        print(f'Plain text: {plaintext}')