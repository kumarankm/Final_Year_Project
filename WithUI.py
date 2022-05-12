from email.mime import message
from cryptosteganography import CryptoSteganography
from Crypto.Cipher import AES
from secrets import token_bytes
import tkinter as tk
from functools import partial


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


def steganographyCipher(ciphertextsteg):
    global secret
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide('img/input_image_name.jpg', 'img/output_image_file.png', ciphertextsteg)
    secret = crypto_steganography.retrieve('img/output_image_file.png')
    # print(secret)
   

def steganographyNonce(ciphertextsteg):
    global Noncee
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide('img/nonce.jpg', 'img/nonce_output.png', ciphertextsteg)
    Noncee = crypto_steganography.retrieve('img/nonce_output.png')

def steganographyTag(ciphertextsteg):
    global Tagg
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide('img/tag.jpg', 'img/tag_output.png', ciphertextsteg)
    Tagg = crypto_steganography.retrieve('img/tag_output.png')

def doEncrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def doDecrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False



def encrypt():
    Message = inputtxt.get(1.0, "end-1c")
    nonce, ciphertext, tag = doEncrypt(Message)
    steganographyCipher(ciphertext)
    steganographyNonce(nonce)
    steganographyTag(tag)


def decrypt():
    doDecrypt(secret,Noncee,Tagg)
    plaintext = doDecrypt(Noncee, secret, Tagg)
    
    lb2.config(text = f'Cipher text: {secret}')
    if not plaintext:
        print('Message is corrupted')
    else:
        # print(f'Plain text: {plaintext}')
        lb1.config(text = f'Plain text: {plaintext}')


def startt():
    lbll.pack_forget()
    starting.pack_forget()


    global inputtxt
    lb3 = tk.Label(root, text = "")
    lb3.config(bg='#000000', height=5)
    lb3.pack()
    inputtxt = tk.Text(root,height = 5,width = 100,font=("Courier",10))
    inputtxt.config(bg='#000000',fg='#ffffff',height = 10,width = 50)
    inputtxt.pack()

    global Message
    

    encryptt = tk.Button(root, text = 'Encyption',command=encrypt, font=("Courier",12))
    encryptt.config(height = 3,width = 15)
    encryptt.pack(side = 'top',pady=30) 

    decryptt = tk.Button(root, text = 'Decryption',command=decrypt, font=("Courier",12))
    decryptt.config(height = 3,width = 15)
    decryptt.pack(side = 'top',pady=30) 

    global lb1
    global lb2

    lb1 = tk.Label(root, text = "",font=("Courier",12))
    lb1.config(bg='#000000',fg='#00ff44',height = 5)
    lb1.pack()

    lb2 = tk.Label(root, text = "",font=("Courier",12))
    lb2.config(bg='#000000',fg='#ffffff')
    lb2.pack()

    
 

if __name__ == '__main__':
    key = token_bytes(16)

     

    root = tk.Tk()    
    root.geometry('1750x700')  
    root.title('Image Based Encryption System')
    root.configure(bg='#000000')

    lbll = tk.Label(root, text = "Welcome to Image Based Encryption Software", font=("Courier",20))
    lbll.config(bg='#000000',fg='#ff0',height = 10,width = 50)
    lbll.pack()


    starting = tk.Button(root, text = 'Start',command=startt, font=("Courier",12))
    starting.config(height = 3,width = 15)
    starting.pack(side = 'top',pady=30,)  









root.mainloop()

