from PIL import Image
from numpy import asarray
import numpy as np


image = Image.open('img/output_image_file.png')
data = asarray(image)
arr = np.array(data)
arr1,arr2,arr3,arr4 = np.array_split(arr, 4)
firstcon = np.concatenate((arr1,arr2))
secondcon = np.concatenate((firstcon,arr3))
final = np.concatenate((secondcon,arr4))

print(final)
pil_image=Image.fromarray(final)
pil_image.show()
