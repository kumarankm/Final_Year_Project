from cryptosteganography import CryptoSteganography

crypto_steganography = CryptoSteganography('My secret password key')

# Save the encrypted file inside the image
crypto_steganography.hide('img/input_image_name.jpg', 'img/output_image_file.png', 'My secrett')

secret = crypto_steganography.retrieve('img/output_image_file.png')

print(secret)