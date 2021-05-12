from tkinter import *
import json
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode
from base64 import b64decode

class GUI():
    def encryptRSA(self):
        if(self.authValue.get()==True)&(self.confValue.get()==True):
            self.archivo = filedialog.askopenfilename(initialdir = '/', title = 'Select file')
            self.lblNombreArchivo.config(text = self.archivo)
            self.aesKey = get_random_bytes(16)
            self.aesCipher = AES.new(self.aesKey, AES.MODE_CBC)
            self.ct_bytes = self.aesCipher.encrypt(pad(open(self.archivo, 'rb').read(), AES.block_size))
            self.iv = b64encode(self.aesCipher.iv).decode('utf-8')
            self.ct = b64encode(self.ct_bytes).decode('utf-8')
            self.result = json.dumps({'iv':self.iv, 'ciphertext':self.ct})
            self.archivo2 = filedialog.askopenfilename(initialdir = '/', title = 'Select private key')
            self.lblNombreLlavePriv.config(text = self.archivo2)
            self.privKey = RSA.import_key(open(self.archivo2, 'r').read())
            self.h = SHA256.new(self.aesKey)
            self.signature = pkcs1_15.new(self.privKey).sign(self.h)
            self.archivo3 = filedialog.askopenfilename(initialdir = '/', title = 'Select public key')
            self.lblNombreLlavePub.config(text = self.archivo3)
            self.pubKey = RSA.import_key(open(self.archivo3, 'r').read())
            self.cipher = PKCS1_v1_5.new(self.pubKey)
            self.cipherText = self.cipher.encrypt(self.aesKey+self.h.digest())
            self.newFile = open('conf_auth_c.txt', 'wb')
            self.newFile.write(self.result.encode())
            self.newFile.write(b'\n-----------------------------------------------------\n')
            self.newFile.write(self.cipherText)
            self.newFile.write(b'\n-----------------------------------------------------\n')
            self.newFile.write(self.signature)
            self.newFile.close()
            self.info = messagebox.showinfo('All done!', 'Encryption successful!')
        elif (self.authValue.get()==True):
            self.archivo = filedialog.askopenfilename(initialdir = '/', title = 'Select file')
            self.lblNombreArchivo.config(text = self.archivo)
            self.archivo2 = filedialog.askopenfilename(initialdir = '/', title = 'Select private key')
            self.lblNombreLlavePriv.config(text = self.archivo2)
            self.privKey = RSA.import_key(open(self.archivo2, 'r').read())
            self.h = SHA256.new(open(self.archivo, 'rb').read())
            self.signature = pkcs1_15.new(self.privKey).sign(self.h)
            self.plainText = open(self.archivo, 'rb').read()
            self.newFile = open('auth_c.txt', 'wb')
            self.newFile.write(self.plainText)
            self.newFile.write(b'\n-----------------------------------------------------\n')
            self.newFile.write(self.signature)
            self.newFile.close()
            self.info = messagebox.showinfo('All done!', 'Encryption successful!')
        elif(self.confValue.get()==True):
            self.archivo = filedialog.askopenfilename(initialdir = '/', title = 'Select file')
            self.lblNombreArchivo.config(text = self.archivo)
            self.aesKey = get_random_bytes(16)
            self.aesCipher = AES.new(self.aesKey, AES.MODE_CBC)
            self.ct_bytes = self.aesCipher.encrypt(pad(open(self.archivo, 'rb').read(), AES.block_size))
            self.iv = b64encode(self.aesCipher.iv).decode('utf-8')
            self.ct = b64encode(self.ct_bytes).decode('utf-8')
            self.result = json.dumps({'iv':self.iv, 'ciphertext':self.ct})
            self.newFile = open('conf_c.txt', 'wb')
            self.newFile.write(self.result.encode())
            self.newFile.write(b'\n-----------------------------------------------------\n')
            self.newFile.write(self.aesKey)
            self.newFile.close()
            self.info = messagebox.showinfo('All done!', 'Encryption successful!')
        else:
            self.info = messagebox.showwarning('Ooops!', 'Not encryption type selected!')

    def decryptRSA(self):
        if(self.authValue.get()==True)&(self.confValue.get()==True):
            self.archivo = filedialog.askopenfilename(initialdir = '/', title = 'Select file')
            self.lblNombreArchivo.config(text = self.archivo)
            self.separate = open(self.archivo, 'rb').read().split(b'\n-----------------------------------------------------\n')
            self.archivo2 = filedialog.askopenfilename(initialdir = '/', title = 'Select private key')
            self.lblNombreLlavePriv.config(text = self.archivo2)
            self.privKey = RSA.import_key(open(self.archivo2, 'r').read())
            self.dsize = SHA256.digest_size
            self.sentinel = Random.new().read(15+self.dsize)
            self.cipher2 = PKCS1_v1_5.new(self.privKey)
            self.message = self.cipher2.decrypt(self.separate[1], self.sentinel)
            self.archivo3 = filedialog.askopenfilename(initialdir = '/', title = 'Select public key')
            self.lblNombreLlavePub.config(text = self.archivo3)
            self.pubKey = RSA.import_key(open(self.archivo3, 'r').read())
            self.a = len(self.message)-16
            self.h1 = SHA256.new(self.message[:-self.a])
            try:
                pkcs1_15.new(self.pubKey).verify(self.h1, self.separate[2])
                self.b64 = json.loads(self.separate[0])
                self.iv = b64decode(self.b64['iv'])
                self.ct = b64decode(self.b64['ciphertext'])
                self.aesCipher = AES.new(self.message[:-self.a], AES.MODE_CBC, self.iv)
                self.pt = unpad(self.aesCipher.decrypt(self.ct), AES.block_size)
                self.newFile1 = open('conf_auth_d.txt', 'wb')
                self.newFile1.write(self.pt)
                self.newFile1.close()
                self.info1 = messagebox.showinfo('All done!', 'Decryption successful!')
            except(ValueError, TypeError):
                self.info1 = messagebox.showerror('Ooops!', 'Something is wrong!')
        elif (self.authValue.get()==True):
            self.archivo = filedialog.askopenfilename(initialdir = '/', title = 'Select file')
            self.lblNombreArchivo.config(text = self.archivo)
            self.separate = open(self.archivo, 'rb').read().split(b'\n-----------------------------------------------------\n')
            self.archivo3 = filedialog.askopenfilename(initialdir = '/', title = 'Select public key')
            self.lblNombreLlavePub.config(text = self.archivo3)
            self.pubKey = RSA.import_key(open(self.archivo3, 'r').read())
            self.h1 = SHA256.new(self.separate[0])
            try:
                pkcs1_15.new(self.pubKey).verify(self.h1, self.separate[1])
                self.newFile1 = open('auth_d.txt', 'wb')
                self.newFile1.write(self.separate[0])
                self.newFile1.close()
                self.info1 = messagebox.showinfo('All done!', 'Authentication successful!')
            except(ValueError, TypeError):
                self.info1 = messagebox.showerror('Ooops!', 'Invalid signature!')
        elif (self.confValue.get()==True):
            self.archivo = filedialog.askopenfilename(initialdir = '/', title = 'Select file')
            self.lblNombreArchivo.config(text = self.archivo)
            self.separate = open(self.archivo, 'rb').read().split(b'\n-----------------------------------------------------\n')
            try:
                self.b64 = json.loads(self.separate[0])
                self.iv = b64decode(self.b64['iv'])
                self.ct = b64decode(self.b64['ciphertext'])
                self.aesCipher = AES.new(self.separate[1], AES.MODE_CBC, self.iv)
                self.pt = unpad(self.aesCipher.decrypt(self.ct), AES.block_size)
                self.newFile1 = open('conf_d.txt', 'wb')
                self.newFile1.write(self.pt)
                self.newFile1.close()
                self.info1 = messagebox.showinfo('All done!', 'Confidenciality successful!')
            except(ValueError, TypeError):
                self.info1 = messagebox.showerror('Ooops!', 'Invalid data!')
        else:
            self.info = messagebox.showwarning('Ooops!', 'Not deryption type selected!')
            

    def __init__(self):
        self.archivo = ''
        self.archivo2 = ''
        self.archivo3 = ''
        self.root = Tk()
        self.root.title("PGP")
        self.root.iconbitmap("pythonIcon.ico")
        self.Frame = Frame()
        self.Frame.pack()
        self.Frame.config(bd="10")
        #self.b1 = Button(self.Frame, text="Select File", command = lambda: self.askFile())
        #self.b1.grid(row=0, column=0, sticky='N')
        self.b2 = Button(self.Frame, text="Encrypt", command = lambda: self.encryptRSA())
        self.b2.grid(row=1, column=0, sticky='E')
        self.b3 = Button(self.Frame, text="Decrypt", command = lambda: self.decryptRSA())
        self.b3.grid(row=2, column=0, sticky='E')
        self.b4 = Button(self.Frame, text = 'Exit', command = self.root.destroy)
        self.b4.grid(row=3, column=0, sticky='E')
        self.authValue = BooleanVar()
        self.authButton = Checkbutton(self.Frame, text='Authentication', var = self.authValue)
        self.authButton.grid(row=4, column=0)
        self.confValue = BooleanVar()
        self.confButton = Checkbutton(self.Frame, text='Confidenciality', var = self.confValue)
        self.confButton.grid(row=4, column=1)
        self.lblNombreArchivo = Label(self.Frame, text = '')
        self.lblNombreArchivo.grid(row=5, column=0)
        self.lblNombreLlavePriv = Label(self.Frame, text = '')
        self.lblNombreLlavePriv.grid(row=6, column=0)
        self.lblNombreLlavePub = Label(self.Frame, text = '')
        self.lblNombreLlavePub.grid(row=7, column=0)
        self.root.mainloop()

gui = GUI()