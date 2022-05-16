from email.mime import message
from cryptosteganography import CryptoSteganography
from Crypto.Cipher import AES
from secrets import token_bytes
from tkinter import *  
from tkinter.ttk import *

from PIL import Image
from numpy import asarray
import numpy as np

import time

key = token_bytes(16)

def splitImgArray():
    image = Image.open('img/output_image_file.png')
    data = asarray(image)
    arr = np.array(data)
    arr1,arr2,arr3,arr4 = np.array_split(arr, 4)
    #arr1, arr2, arr3, arr4 are the segments stored on database
    
    firstcon = np.concatenate((arr1,arr2))
    secondcon = np.concatenate((firstcon,arr3))
    final = np.concatenate((secondcon,arr4))

    pil_image=Image.fromarray(final)
    return pil_image
    # pil_image.show()

def steganographyCipher(ciphertextsteg):
    global secret
    crypto_steganography = CryptoSteganography(keyy)
    crypto_steganography.hide('img/input_image_name.jpg', 'img/output_image_file.png', ciphertextsteg)
    imgArr = splitImgArray()
    secret = crypto_steganography.retrieve(imgArr)
   

def steganographyNonce(ciphertextsteg):
    global Noncee
    crypto_steganography = CryptoSteganography(keyy)
    crypto_steganography.hide('img/nonce.jpg', 'img/nonce_output.png', ciphertextsteg)
    Noncee = crypto_steganography.retrieve('img/nonce_output.png')

def steganographyTag(ciphertextsteg):
    global Tagg
    crypto_steganography = CryptoSteganography(keyy)
    crypto_steganography.hide('img/tag.jpg', 'img/tag_output.png', ciphertextsteg)
    Tagg = crypto_steganography.retrieve('img/tag_output.png')

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag, keydec):
    if keydec == keyy:
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return plaintext.decode('ascii')
        except:
            return False
    else:
        print("Wrong key")
        print(" ")
        print("Thank you for using our software!")
        print(" ")
        exit()
        

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

if __name__ == '__main__':
    try:
        print(" ")
        print("***********Welcome to Image based encryption System***********")
        print(" ")
        Message = input("Enter a message: ")
        print(" ")

        print("Doing encryption....")
        time.sleep(1.2)
        nonce, ciphertext, tag = encrypt(Message)
        print("Encryption Done")
        time.sleep(1.2)
        print(" ")
        print("Cipher text is: ", ciphertext)
        print(" ")

        inp = input("Do you wanna proceed with steganography? y/n : ")
        if(inp == "y" or inp == "Y"):
            global keyy
            print(" ")
            keyy = input("Enter a key to be hidden on image: ")
            print(" ")
            print("Doing steganography....")
            time.sleep(1.2)
            steganographyCipher(ciphertext)
            steganographyNonce(nonce)
            steganographyTag(tag)
            print("Done with steganography")
            print(" ")
            inpp = input("Do you wanna proceed with decyption? y/n : ")
            time.sleep(1.2)
            print(" ")
            keydec = input("Enter a key to retrieve from image: ")
            print(" ")
            if(inpp == "y" or inpp=="Y"):
                plaintext = decrypt(Noncee, secret, Tagg, keydec)
                if not plaintext:
                    print('Message is corrupted')
                else:
                    print(f'Plain text is: {plaintext}')
    finally:
        print(" ")
        print("Thank you for using our software!")
        print(" ")
