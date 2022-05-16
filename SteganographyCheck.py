from cryptosteganography import CryptoSteganography

crypto_steganography = CryptoSteganography('My secret password key')

print("Enter a message: ")
# Save the encrypted file inside the image
crypto_steganography.hide('img/input_image_name.jpg', 'img/output_image_file.png', input())

secret = crypto_steganography.retrieve('img/output_image_file.png')

print(" ")
print(secret)