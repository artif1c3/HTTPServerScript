import os
import datetime
import colorama
import zipfile
import tarfile
import base64
import tempfile
import hashlib

from zipfile import ZipFile
from Cryptodome.Cipher import AES
from werkzeug.utils import secure_filename
from flask import Flask, send_from_directory, request

colorama.init()

mypwd = 'password123'  # Change the password used to decrypt.

app = Flask(__name__)
app.config['UPLOAD_DIR'] = '/home/you/Documents/upload'    # Path to upload directory
app.config['DOWNLOAD_DIR'] = '/home/you/Documents/download' # Path to download directory
app.config['AUTO_EXTRACT'] = False   # Set to True to auto extract to folder
app.config['AUTO_DECRYPT'] = False  # Set to True to auto decrypt


def decrypt_input(encrypted, password, iterations=10000):
    # Used to decrypt tar when piped through openssl then curl
    # e.g. openssl -md sha256 -aes-256-cbc -pbkdf2 -e -a -pass 'pass:password123'
    # 
    # It will not decrypt a pre-archived tar file or zip upon upload.
    # See sample command in README.md 
    try:
        salt = encrypted[8:16]
        passwordBytes = password.encode('utf-8')
        derivedKey = hashlib.pbkdf2_hmac('sha256', passwordBytes, salt, iterations, 48)
        key = derivedKey[0:32]
        iv = derivedKey[32:48]
        ciphertext = encrypted[16:]
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        plaintext = decryptor.decrypt(ciphertext)

        return plaintext[:-plaintext[-1]]

    except IndexError as e:
        print(f'Index error during decryption: {e}')
        return b''


def test_zipfile(zip):
    test = zip.testzip()
    members = zip.infolist()

    if test is not None:
        return False

    for member in members:
        filepath = os.path.normpath(member.filename)

        if filepath.startswith('..') or os.path.isabs(filepath):
            return False

    return True


def test_tarfile(tar):
    if tar.errorlevel == 2:
        return False

    for member in tar:
        filepath = os.path.normpath(member.name)

        if filepath.startswith('..') or os.path.isabs(filepath):
            return False

    return True


def auto_extract_zip(f, upload):
    f.stream.seek(0)

    zip_file = ZipFile(f)

    if not test_zipfile(zip_file):
        raise Exception(f'\n\033[1m\033[31mFAILURE! Zip file has unsafe members.')

    zip_file.extractall(upload)

    message = f'\033[1m\033[32mSUCCESS! {f} is now in {upload}!'
    zip_file.close()

    return message


def auto_extract_tar(f, upload):
    f.stream.seek(0)

    tararchive = tarfile.open(fileobj=f.stream, mode='r')

    if not test_tarfile(tararchive):
        raise Exception(f'\n\033[1m\033[31mFAILURE! Tar file has unsafe members.')

    tararchive.extractall(upload)

    message = f'\033[1m\033[32mSUCCESS! {f} is now in {upload}!'
    tararchive.close()

    return message


@app.route('/', methods=['POST'])
# Zip and tar files will automatically be extracted upon upload,
# if app.config['AUTO_EXTRACT'] is set to True.
#
# Tar is decrypted automatically if app.config['AUTO_DECRYPT'] is set to True.
# If both are set to False, the zip or tar will be saved to server.
# Creates an upload file if it doesn't exist already.
def upload_file():
    try:
        for f in request.files.values():
            if request.args.get('enc', default=False, type=bool) and app.config['AUTO_DECRYPT']:
                decodedStream = base64.b64decode(f.stream.read())  
                decryptedFile = decrypt_input(decodedStream, app.config.get('ENCRYPT_PASS', mypwd))
                f.stream = tempfile.SpooledTemporaryFile()
                f.stream.write(decryptedFile)

            upload = os.path.join(app.config['UPLOAD_DIR'], request.remote_addr)

            if not os.path.exists(upload):
                    os.makedirs(upload)

            if zipfile.is_zipfile(f.stream) and app.config['AUTO_EXTRACT']:
                message = auto_extract_zip(f, upload)

            elif tarfile.is_tarfile(f.stream) and app.config['AUTO_EXTRACT']:
                message = auto_extract_tar(f, upload)

            else:
                timestamp = datetime.datetime.now().strftime('%d-%b-%Y-%H-%M-%S')
                file = secure_filename(f"{timestamp}.{f.filename}")
                f.stream.seek(0)
                f.save(os.path.join(upload, file))
                message = f'\033[1m\033[32mSUCCESS! {file} is now in {upload}!'

    except Exception as e:
        failed = f'{e}'
        print(e)
        return failed

    print(message)
    return message


@app.route('/<filename>', methods=['GET'])
def download_file(filename):
    # Allows you to download a file from the download folder,
    # use wget command to download the file.
    #
    # Download folder is created if it doesn't exist in your path,
    # and make sure the file is inside the folder.
    download = os.path.join(app.root_path, app.config['DOWNLOAD_DIR'])

    if not os.path.exists(download):
        os.mkdir(download)
        message = f'\n\033[1m\033[31mERROR: looks like {download} is non-existent.'
        message += f'\n{download} has been created.'
        message += f'\n\033[31mPlease store ' + f'\033[32m{filename}' + f' \033[31min {download}.'
        raise Exception(message)

    file_path = os.path.join(download, filename)
    if os.path.exists(file_path):
        print(f'\033[1m\033[32mSUCCESS! {filename} transferred to {request.remote_addr}')
        return send_from_directory(download, filename)
    else:
        message = f'\n\033[1m\033[31mERROR: looks like ' + f'\033[32m{filename}' + ' \033[1m\033[31mis non-existent.'
        message += f'\n\033[1m\033[31mAre you sure file exists or is in {download}?'
        raise Exception(message)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)