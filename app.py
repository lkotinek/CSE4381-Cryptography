from flask import Flask, render_template, request, send_file, redirect, url_for
import os
import secrets
import io
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from zipfile import ZipFile

app = Flask(__name__)

userFile = 'users.txt'  

def loadUsers(): 
    users = {}
    try:
        with open(userFile, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    username, password = line.split(':', 1)   
                    users[username] = password 
    except FileNotFoundError:
        open(userFile, 'w').close()
    return users 
 
def saveUsers(users):
    with open(userFile, 'w') as f:
        for username, password in users.items(): 
            f.write(f"{username}:{password}\n")

def generatePassword(length=16):
    return secrets.token_urlsafe(length)[:length]  

def generateSymmetricKey(algorithm='AES', keySize=None):
    if algorithm.upper() == '3DES':
        return os.urandom(24)
    elif algorithm.upper() == 'AES':
        if keySize == 128: 
            return os.urandom(16) 
        elif keySize == 256:
            return os.urandom(32)

def generateKeyPair(keyType='RSA', dhParams=None):
    if keyType.upper() == 'RSA':
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    elif keyType.upper() == 'DH' and dhParams:
        privateKey = dhParams.generate_private_key()
 
    publicKey = privateKey.public_key()
    privPem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,   
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pubPem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    zipBuffer = io.BytesIO()
    with ZipFile(zipBuffer, 'w') as zipFile: 
        zipFile.writestr(f'{keyType}_private.pem', privPem)
        zipFile.writestr(f'{keyType}_public.pem', pubPem)  
    zipBuffer.seek(0)

    return send_file(
        zipBuffer,
        as_attachment=True,  
        download_name=f'{keyType}_keys.zip'
    )

def performDhKeyExchange(privateKey, peerPublicKey):  
    sharedKey = privateKey.exchange(peerPublicKey)   
    derivedKey = hashes.Hash(hashes.SHA256())
    derivedKey.update(sharedKey)
    return derivedKey.finalize()[:32]
 
def encryptFileSymmetric(inputFile, key, algorithm='AES', mode='CBC'):
    plaintext = inputFile.read()
    iv = b''
    blockSize = 128 if algorithm == 'AES' else 64

    if algorithm == 'AES':
        cipherCls = algorithms.AES
        if mode == 'CBC':  
            ivLength = 16
        else:
            ivLength = 0 
    elif algorithm == '3DES':
        cipherCls = algorithms.TripleDES
        ivLength = 8
  
    if mode == 'CBC' and ivLength > 0:  
        iv = os.urandom(ivLength)
        cipherMode = modes.CBC(iv)  
    elif mode == 'ECB': 
        cipherMode = modes.ECB()

    padder = padding.PKCS7(blockSize).padder()
    paddedData = padder.update(plaintext) + padder.finalize()
 
    cipher = Cipher(cipherCls(key), cipherMode)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedData) + encryptor.finalize()

    return io.BytesIO(iv + ciphertext)    

def decryptFileSymmetric(inputFile, key, algorithm='AES', mode='CBC'):
    ciphertext = inputFile.read()
    blockSize = 128 if algorithm == 'AES' else 64
  
    iv = b''
    if mode == 'CBC':
        ivLength = 16 if algorithm == 'AES' else 8 
        iv, ciphertext = ciphertext[:ivLength], ciphertext[ivLength:]

    cipherCls = algorithms.AES if algorithm == 'AES' else algorithms.TripleDES
    cipherMode = modes.CBC(iv) if mode == 'CBC' else modes.ECB()
 
    cipher = Cipher(cipherCls(key), cipherMode)   
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(blockSize).unpadder()
    return io.BytesIO(unpadder.update(decrypted) + unpadder.finalize()) 

def encryptFileAsymmetric(inputFile, publicKey):
    plaintext = inputFile.read()     
    ciphertext = publicKey.encrypt(
        plaintext,
        asympadding.OAEP( 
            mgf=asympadding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),    
            label=None
        )
    )
    return io.BytesIO(ciphertext)

def decryptFileAsymmetric(inputFile, privateKey):
    ciphertext = inputFile.read()
    plaintext = privateKey.decrypt(
        ciphertext,
        asympadding.OAEP(   
            mgf=asympadding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return io.BytesIO(plaintext)  

def hashFile(inputFile, algorithm='SHA256'):  
    hasher = hashes.Hash(getattr(hashes, algorithm)())
    while chunk := inputFile.read(4096):
        hasher.update(chunk) 
    return io.BytesIO(hasher.finalize())

def compareFileHashes(file1, file2, algorithm='SHA256'):
    hash1 = hashFile(file1, algorithm).getvalue()
    hash2 = hashFile(file2, algorithm).getvalue() 
    return io.BytesIO(f"Files {'match' if hash1 == hash2 else 'do not match'}".encode())

 
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    users = loadUsers()
    if request.method == 'POST':
        if 'login' in request.form:
            username = request.form['username']
            password = request.form['password']
            if username in users and users[username] == password:
                return redirect(url_for('gui'))
           
        elif 'register' in request.form:
            username = request.form['newUsername'] 
            password = request.form['newPassword']
            if username not in users:
                users[username] = password
                saveUsers(users)

        elif 'delete' in request.form:
            usernameToDelete = request.form['delUsername']
            if usernameToDelete in users:
                del users[usernameToDelete]
                saveUsers(users)
    
    return render_template('login.html', users=users.keys()) 

@app.route('/gui')
def gui():
    return render_template('gui.html')

@app.route('/logout')
def logout():
    return redirect(url_for('login'))

@app.route('/generatePassword', methods=['POST'])
def returnPassword():
    length = int(request.form.get('length'))   
    output = io.BytesIO(generatePassword(length).encode())
    return send_file(output, as_attachment=True, download_name='password.txt')

@app.route('/generateSymmetricKey', methods=['POST'])
def returnSymmetricKey():
    algorithm = request.form.get('algorithm')
    keySize = int(request.form.get('keySize')) if algorithm == 'AES' else None
    key = generateSymmetricKey(algorithm, keySize)
    output = io.BytesIO(key.hex().encode())
    return send_file(output, as_attachment=True, download_name=f'{algorithm}_key.txt')

@app.route('/generateKeyPair', methods=['POST'])  
def returnKeyPair():
    return generateKeyPair('RSA')

@app.route('/generateDhKeyPair', methods=['POST'])
def returnDhKeyPair():
    params = serialization.load_pem_parameters(request.files['dhParams'].read())
    return generateKeyPair('DH', params)

@app.route('/encryptSymmetric', methods=['POST'])   
def returnEncryptSymmetric():
    file = request.files['file']
    keyFile = request.files['keyFile']
    key = bytes.fromhex(keyFile.read().decode().strip())
    encrypted = encryptFileSymmetric(file, key, request.form['algorithm'], request.form['mode'])
    return send_file(encrypted, as_attachment=True, download_name='encrypted.bin')

@app.route('/decryptSymmetric', methods=['POST'])
def returnDecryptSymmetric():
    file = request.files['file']  
    keyFile = request.files['keyFile']
    key = bytes.fromhex(keyFile.read().decode().strip())  
    decrypted = decryptFileSymmetric(file, key, request.form['algorithm'], request.form['mode'])
    return send_file(decrypted, as_attachment=True, download_name='decrypted.txt')

@app.route('/encryptAsymmetric', methods=['POST'])
def returnEncryptAsymmetric(): 
    file = request.files['file'] 
    pubKeyFile = request.files['publicKey']  
    pubKey = serialization.load_pem_public_key(pubKeyFile.read())
    encrypted = encryptFileAsymmetric(file, pubKey)
    return send_file(encrypted, as_attachment=True, download_name='encrypted_rsa.bin')

@app.route('/decryptAsymmetric', methods=['POST'])
def returnDecryptAsymmetric():
    file = request.files['file']
    privKeyFile = request.files['privateKey']
    privKey = serialization.load_pem_private_key(
        privKeyFile.read(),
        password=None
    )  
    decrypted = decryptFileAsymmetric(file, privKey)
    return send_file(decrypted, as_attachment=True, download_name='decrypted_rsa.txt')

@app.route('/hashFile', methods=['POST'])
def returnHash():
    file = request.files['file']
    algorithm = request.form.get('algorithm', 'SHA256')
    hashed = hashFile(file, algorithm)
    return send_file(hashed, as_attachment=True, download_name='hash.bin')

@app.route('/compareHashes', methods=['POST'])
def returnCompare():
    file1 = request.files['file1']
    file2 = request.files['file2']
    algorithm = request.form.get('algorithm', 'SHA256')
    result = compareFileHashes(file1, file2, algorithm)
    return send_file(result, as_attachment=True, download_name='hash_comparison_result.txt')

@app.route('/generateDhParams', methods=['POST'])
def returnDhParams(): 
    params = dh.generate_parameters(generator=2, key_size=1024)
    output = io.BytesIO(params.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))
    return send_file(output, as_attachment=True, download_name='dh_params.pem')  

@app.route('/performDh', methods=['POST'])
def returnDh():
    private = serialization.load_pem_private_key(request.files['privateKey'].read(), password=None) 
    peerPublic = serialization.load_pem_public_key(request.files['peerPublicKey'].read())
    secret = performDhKeyExchange(private, peerPublic)
    output = io.BytesIO(secret.hex().encode())
    return send_file(output, as_attachment=True, download_name='shared_secret.txt')

if __name__ == '__main__':
    app.run() 

