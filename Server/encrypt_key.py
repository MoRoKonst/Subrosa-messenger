from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import getpass

# Читаем незашифрованный ключ
with open('key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Запрашиваем пароль
password = getpass.getpass("Введите пароль для шифрования ключа: ")
password_confirm = getpass.getpass("Повторите пароль: ")

if password != password_confirm:
    print("Пароли не совпадают!")
    exit(1)

# Сохраняем зашифрованный ключ
encrypted_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
)

with open('key_encrypted.pem', 'wb') as f:
    f.write(encrypted_pem)

print("✅ Ключ зашифрован и сохранён в key_encrypted.pem")