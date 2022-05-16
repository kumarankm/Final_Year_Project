#module for cryptography
from email.mime import message
from cryptosteganography import CryptoSteganography
from Crypto.Cipher import AES
from secrets import token_bytes
import tkinter as tk
from functools import partial

#module for numpy
from PIL import Image
from numpy import asarray
import numpy as np

#Function for splitting ciphertext but never used
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


#Funcation to split Stored Ciphertext Image
def splitImgArray(imgfile):
    image = Image.open(imgfile)
    data = asarray(image)
    arr = np.array(data)
    arr1,arr2,arr3,arr4 = np.array_split(arr, 4)
    #arr1, arr2, arr3, arr4 are the segments stored on database

    ArrFirst = Image.fromarray(arr1)
    ArrSecond = Image.fromarray(arr2)
    ArrThird = Image.fromarray(arr3)
    ArrFourth = Image.fromarray(arr4)

    if imgfile == "img/output_image_file.png":
        ArrFirst.save("DataBase/cipher/arr1.png")
        ArrSecond.save("DataBase/cipher/arr2.png")
        ArrThird.save("DataBase/cipher/arr3.png")
        ArrFourth.save("DataBase/cipher/arr4.png")

        f = open("DataBase/img1.txt", "w")
        f.write(str(arr1))
        f.close()

        f = open("DataBase/img2.txt", "w")
        f.write(str(arr2))
        f.close()

        f = open("DataBase/img3.txt", "w")
        f.write(str(arr3))
        f.close()

        f = open("DataBase/img4.txt", "w")
        f.write(str(arr4))
        f.close()

    elif imgfile == "img/nonce_output.png":
        ArrFirst.save("DataBase/nonce/arr1.png")
        ArrSecond.save("DataBase/nonce/arr2.png")
        ArrThird.save("DataBase/nonce/arr3.png")
        ArrFourth.save("DataBase/nonce/arr4.png")
    else:
        ArrFirst.save("DataBase/tag/arr1.png")
        ArrSecond.save("DataBase/tag/arr2.png")
        ArrThird.save("DataBase/tag/arr3.png")
        ArrFourth.save("DataBase/tag/arr4.png")

    

    final = np.concatenate((arr1,arr2,arr3,arr4))

    pil_image=Image.fromarray(final)
    return pil_image
    # pil_image.show()

#Doing steganography for ciphertext
def steganographyCipher(ciphertextsteg):
    global secret
    global keyy
    keyy = inputtxt1.get(1.0, "end-1c")

    crypto_steganography = CryptoSteganography(keyy)
    crypto_steganography.hide('img/input_image_name.jpg', 'img/output_image_file.png', ciphertextsteg)
    imgfil = 'img/output_image_file.png'
    imgArr = splitImgArray(imgfil)
    secret = crypto_steganography.retrieve(imgArr)
   
   
#Doing steganography for Nonce
def steganographyNonce(ciphertextNonce):
    global Noncee
    crypto_steganography = CryptoSteganography(keyy)
    crypto_steganography.hide('img/nonce.jpg', 'img/nonce_output.png', ciphertextNonce)
    imgfil = 'img/nonce_output.png'
    imgArr = splitImgArray(imgfil)
    Noncee = crypto_steganography.retrieve(imgArr)


#Doing steganography for Tag
def steganographyTag(ciphertextTag):
    global Tagg
    crypto_steganography = CryptoSteganography(keyy)
    crypto_steganography.hide('img/tag.jpg', 'img/tag_output.png', ciphertextTag)
    imgfil = 'img/tag_output.png'
    imgArr = splitImgArray(imgfil)
    Tagg = crypto_steganography.retrieve(imgArr)


#Doing encryption
def doEncrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag


#Doing decryption
def doDecrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False


#Function wil get executed once the encryption button is clicked
def encrypt():
    Message = inputtxt.get(1.0, "end-1c")
    nonce, ciphertext, tag = doEncrypt(Message)
    steganographyCipher(ciphertext)
    steganographyNonce(nonce)
    steganographyTag(tag)
    lb2.config(text = f'Cipher text: {secret}')


#Function wil get executed once the decryption button is clicked
def decrypt():
    
    plaintext = doDecrypt(Noncee, secret, Tagg)
    
    if not plaintext:
        print('Message is corrupted')
    else:
        # print(f'Plain text: {plaintext}')
        keydec = inputtxt11.get(1.0, "end-1c")
        if keyy == keydec:
            lb1.config(text = f'Plain text: {plaintext}')
        else:
            lb1.config(text = "Key Doesn't Match. Thank You!")


#Starting our software
def startt():
    lbll.pack_forget()
    starting.pack_forget()


    global inputtxt
    global inputtxt1
    global inputtxt11

    lb3 = tk.Label(root, text = "")
    lb3.config(bg='#000000', height=5)
    lb3.pack()

    lbll3 = tk.Label(root, text = "Enter the text to be encrypted: ", font=("Courier",10))
    lbll3.config(bg='#000000',fg='#ff0',height = 2)
    lbll3.pack()


    inputtxt = tk.Text(root,height = 2,width = 100,font=("Courier",10))
    inputtxt.config(bg='#000000',fg='#ffffff',height = 2)
    inputtxt.pack()

    lbll2 = tk.Label(root, text = "Enter key to be hidden on image: ", font=("Courier",10))
    lbll2.config(bg='#000000',fg='#ff0',height = 2,)
    lbll2.pack()

    inputtxt1 = tk.Text(root,height = 2,width = 100,font=("Courier",10))
    inputtxt1.config(bg='#000000',fg='#ffffff',height = 2)
    inputtxt1.pack()

    global Message
    

    encryptt = tk.Button(root, text = 'Encyption',command=encrypt, font=("Courier",12))
    encryptt.config(height = 3,width = 15)
    encryptt.pack(side = 'top',pady=30) 

    global lb2
    lb2 = tk.Label(root, text = "",font=("Courier",12))
    lb2.config(bg='#000000',fg='#ffffff')
    lb2.pack()

    lbll222 = tk.Label(root, text = " ", font=("Courier",10))
    lbll222.config(bg='#000000',fg='#ff0',height = 2,)
    lbll222.pack()

    lbll22 = tk.Label(root, text = "Enter key to retrieve from image: ", font=("Courier",10))
    lbll22.config(bg='#000000',fg='#ff0',height = 2,)
    lbll22.pack()

    inputtxt11 = tk.Text(root,height = 2,width = 100,font=("Courier",10))
    inputtxt11.config(bg='#000000',fg='#ffffff',height = 2)
    inputtxt11.pack()

    decryptt = tk.Button(root, text = 'Decryption',command=decrypt, font=("Courier",12))
    decryptt.config(height = 3,width = 15)
    decryptt.pack(side = 'top',pady=30) 

    global lb1
   

    lb1 = tk.Label(root, text = "",font=("Courier",12))
    lb1.config(bg='#000000',fg='#00ff44',height = 5)
    lb1.pack()

    

    
 
#Main Function
if __name__ == '__main__':
    key = token_bytes(16) #Making 16bit encoding

     
    #tkinter UI
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

