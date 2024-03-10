import sys
import click
from fast_crypt.auth import authenticate, is_user_authorized
from fast_crypt.decrypt import FileSecretsDecryptor
from fast_crypt.encrypt import FileSecretsManager
from fast_crypt.encrypt_name import AESEncryption
from fast_crypt.get_repo import get_current_repo
from fast_crypt.file_path import file_path_prompt


access_token = None


def menu():
    return click.prompt("\nChoose an option:\n0 - Exit\n1 - Encrypt a file\n2 - Decrypt a file", type=int)

@click.command()
def main():
    access_token = authenticate()  # Capture the token returned from authenticate
    if not access_token:
        click.echo("GitHub authentication failed. Exiting FastCrypt.")
        sys.exit()
    repo_full_name = get_current_repo()         
    if not repo_full_name:
        click.echo("Failed to identify repository. Ensure you're within a git repository.")
        return
    if not is_user_authorized(access_token, repo_full_name):
        click.echo("You do not have permission to modify  " + repo_full_name)
        sys.exit(1)
    else:
        click.echo("Access to " + repo_full_name + " granted!")
    aes_encryption = AESEncryption()
    while True:
        choice = menu()
        if choice == 0:
            click.echo("FastCrypt Close.")
            break
        elif choice == 1:
            file_path = file_path_prompt('encrypt')
            if file_path is None:
                click.echo("Back to menu")
                continue
            unique_identifier = repo_full_name + file_path
            encrypted_identifier = aes_encryption.encrypt(unique_identifier)
            file_secret = FileSecretsManager()
            file_secret.encrypt_file_and_store_key(file_path, encrypted_identifier)
        elif choice == 2:
           file_path = file_path_prompt('decrypt')
           if file_path is None:
                click.echo("Back to menu")
                continue
           unique_identifier = repo_full_name + file_path
           encrypted_identifier = aes_encryption.encrypt(unique_identifier)
           file_secret = FileSecretsDecryptor()
           file_path = file_path + '.enc'
           decrypted_identifier = file_secret.decrypt_file(file_path,encrypted_identifier)
          
        else:
            click.echo("Invalid choice. Please select again.")

if __name__ == "__main__":
    main()








