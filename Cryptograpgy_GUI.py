#pip install customtkinter
#pip install Crypto
import tkinter
import customtkinter
from Crypto.Cipher import AES
import pathlib
import os

from Crypto.Protocol.KDF import PBKDF2 #this is for brute force protection
#from Crypto.Random import get_random_bytes
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox as theBox
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


#set the appereance the  the window/system  either light or dark
customtkinter.set_appearance_mode("dark")
#set the theme of the window
customtkinter.set_default_color_theme("blue")

root = customtkinter.CTk()#assigning custom
root.title("The Cryptographer")

root.geometry("480x380")#seting the size of the window

#entering the file--------------
frame = customtkinter.CTkFrame(master = root)
frame.pack(pady=25)

location = StringVar()


def browseFile():
    filepath = filedialog.askopenfilename( initialdir="C:\\Users\\40186210\\source\\Encryption", title="Open cryptography file", 
                                            filetypes = (("all files","*.*"),("text files","*.txt*"),("powerpoint","*.ppt*")))
    location.set(filepath)

btn_Browse = customtkinter.CTkButton(master=frame, command = browseFile ,width = 70, text = "Browse")
btn_Browse.pack(side ="right",padx =(10,10))

ent_Browse = customtkinter.CTkEntry(master = frame, width = 300, placeholder_text= "Select file" ,placeholder_text_color="Silver", textvariable = location)
ent_Browse.pack(side="left", padx = 15)


#Selecting the algorith---------------

rdoMethod = IntVar()

lbl_Method = customtkinter.CTkLabel(master = root, text = "Method:", font = ("helvetica",18))
lbl_Method.place(y=75,x=30)

rdo_AES = customtkinter.CTkRadioButton(master = root, text = "AES", variable =rdoMethod, value =1,  font = ("helvetica",16))
rdo_AES.place(y=78,x=105)

rdo_Custom = customtkinter.CTkRadioButton(master = root, text = "Custom", variable =rdoMethod, value =2 ,  font = ("helvetica",16))
rdo_Custom.place(y=110,x=105)

#Entering the key-------------------------

#key = StringVar()

lbl_Password= customtkinter.CTkLabel(master = root, text = "Password:", font = ("helvetica",18))
lbl_Password.place(y=165,x=13)

txt_Key = customtkinter.CTkEntry(master = root, width = 200, placeholder_text= "Input your key",placeholder_text_color="Silver", show="*")
txt_Key.place(y=165,x=105)



#Encrypt or Decrypt-----------------

rdoCrypt = IntVar()

rdo_Encrypt = customtkinter.CTkRadioButton(master = root, text = "Encrypt", variable =rdoCrypt, value =1 ,  font = ("helvetica",16))
rdo_Encrypt.place(y=223,x=143)

rdo_Decrypt = customtkinter.CTkRadioButton(master = root, text = "Decrypt", variable = rdoCrypt, value =2 ,  font = ("helvetica",16))
rdo_Decrypt.place(y=223,x=250)


#Run and closing application


def processing():
    if ent_Browse.get() !="":           #if file is not chosen
        if txt_Key.get() !="":          #if password is not entered
            if rdoMethod.get() ==1:     #If AES algorith is chosen              
                if rdoCrypt.get()==1:   #If encrypting is chosen

                    key = txt_Key.get()
                    key = key.encode("UTF-8")       #converting key into bytes
                    key = pad(key,AES.block_size)   #padding the key

                    def encryptAES(file_name,key):
                        with open(file_name,'rb') as input:  #openin the file and r³eading the file in bytes
                            data = input.read()         #Things we are reading from the file
                            cipher = AES.new(key,AES.MODE_CFB)          #creating the CFB method to encrypt
                            ciphertext = cipher.encrypt(pad(data,AES.block_size))       #use this method to encrypt file
                            iv= b64encode(cipher.iv).decode("UTF-8")    #writing IV and ciphertext together and placing it in a easier format to read we use the base64 lib
                            ciphertext = b64encode(ciphertext).decode("UTF-8")      #
                            to_write = iv + ciphertext          #writing 
                        os.remove(file_name)

                        input.close()
                        with open(file_name+'.enc','w') as data: #writing file data to new file with .enc extension
                            data.write(to_write)
                        data.close()

                    encryptAES(ent_Browse.get(),key)
                    print("Successfully encrypted")
                    
                elif rdoCrypt.get()==2: #If decrypting is chosen
                    
                    key = txt_Key.get()
                    key = key.encode("UTF-8")
                    key = pad(key,AES.block_size)

                    def decrytionAES(file_name,key): 
                        with open(file_name,'r') as input:
                            try:
                                data = input.read()
                                length = len(data)
                                iv = data[:24]
                                iv = b64decode(iv)
                                ciphertext = data[24:length]
                                ciphertext = b64decode(ciphertext)
                                cipher = AES.new(key,AES.MODE_CFB,iv)
                                decrypted = cipher.decrypt(ciphertext)
                                decrypted = unpad(decrypted,AES.block_size)
                                                        
                                with open(file_name.removesuffix('enc'),'wb') as data:
                                    data.write(decrypted)
                                data.close()
                            except(ValueError,KeyError):
                                theBox.showinfo("Wrong password")
                        os.remove(file_name)
                    
                    decrytionAES(ent_Browse.get(),key)
                    print("Successfully decrypted")
                else:
                    {
                        theBox.showinfo("Encrypt or Decrypt","Please select whether to encrypt or decrypt")
                    }
            elif rdoMethod.get()==2:    #If Custom algorith is chosen 
                
                if rdoCrypt.get()==1:   #If encrypting is chosen
                    salt = b"\xe4'\xa1\x1b\xa4S\xac\xf7^y/>\xc8\x92V\xed\xb5\x08\xb5S\xc4\xee\x9e\xa2\x0c\x89%6\x88\x903\xb1"

                    password = txt_Key.get()    #Hashing

                    key = PBKDF2(password, salt, dkLen=32)

                    def customEncryption(file_name,key):
                        with open(file_name,'rb') as inFile:
                            data = inFile.read()
                            cipher = AES.new(key,AES.MODE_CBC)
                            ciphered = cipher.encrypt(pad(data,AES.block_size))
                        os.remove(file_name)

                        with open(file_name+".bin",'wb') as outFile:
                            outFile.write(cipher.iv)
                            outFile.write(ciphered)
                        outFile.close()

                    customEncryption(ent_Browse.get(),key)
                    print("Successfully encrypted")   
                elif rdoCrypt.get()==2:
                    
                    salt = b"\xe4'\xa1\x1b\xa4S\xac\xf7^y/>\xc8\x92V\xed\xb5\x08\xb5S\xc4\xee\x9e\xa2\x0c\x89%6\x88\x903\xb1"

                    password = txt_Key.get()    

                    key = PBKDF2(password, salt, dkLen=32)  #Hashing

                    def customDecryption(file_name,key):
                        with open(file_name,'rb') as inFile:
                            try:
                                iv = inFile.read(16)
                                decrypt = inFile.read()
            
                                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                                decrypted = unpad(cipher.decrypt(decrypt),AES.block_size)

                                with open(file_name.removesuffix('bin'),'wb') as outFile:
                                    outFile.write(decrypted)
                                    outFile.close()
                            except(ValueError,KeyError):
                                theBox.showinfo("Wrong password")
                        os.remove(file_name)
                    customDecryption(ent_Browse.get(),key)
                    print("Successfully decrypted")        
                else:
                    {
                        theBox.showerror("Encryption or Decrytion error", "Please select whether to encrypt or decrypt")
                    }          
            else:
                {
                    theBox.showerror("Method error","please select an encrytion method")
                }
        else:
            theBox.showerror("Password","Please input the password")
    else:
        theBox.showerror("File error","Please input a file")


btn_Run = customtkinter.CTkButton(master=root, width = 65, text = "Run", command = processing)
btn_Run.place(y=300,x=10)

btn_Close = customtkinter.CTkButton(master=root, width = 65, text = "Close", command= root.destroy)
btn_Close.place(y=300, x=90)

root.mainloop()