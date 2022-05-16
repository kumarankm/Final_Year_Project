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
        print(arr)

    else:
        print(neww)


splitCheck("Hellokishoreeeeeeekumareshkumaranroshannnfo   dafhjewkf")


