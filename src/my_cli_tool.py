import click
import sys

@click.group()
def cli():
    """My CLI Tool"""
    pass

@cli.command()
def encrypt():
    """Encrypt a file"""
    file_path = click.prompt('Enter the path of the file to encrypt, or enter "0" to exit', type=str)
    if file_path == '0':
        exit()  # Exit the program properly
    elif not file_path:
        click.echo('Error: File path cannot be empty.')
        return
    try:
        click.Path(exists=True, dir_okay=False)(file_path)
    except click.exceptions.BadParameter:
        click.echo(f"Error: File '{file_path}' does not exist.")
        return
    # encrypt_file(file_path)
    click.echo(f'File encrypted: {file_path}')

@cli.command()
def decrypt():
    """Decrypt a file"""
    file_path = click.prompt('Enter the path of the file to decrypt, or enter "0" to exit', type=str)
    if file_path == '0':
        exit()  # Exit the program properly
    elif not file_path:
        click.echo('Error: File path cannot be empty.')
        return
    try:
        click.Path(exists=True, dir_okay=False)(file_path)
    except click.exceptions.BadParameter:
        click.echo(f"Error: File '{file_path}' does not exist.")
        return
    # decrypt_file(file_path)
    click.echo(f'File decrypted: {file_path}')

@cli.command()
def exit():
    """Exit the program"""
    click.echo('Exiting...')
    sys.exit()  # Exit the program properly

if __name__ == '__main__':
    while True:
        try:
            choice = click.prompt('Choose an option:\n1. Encrypt\n2. Decrypt\n3. Exit', type=int, default=3, show_default=False)
            if choice == 1:
                encrypt()
            elif choice == 2:
                decrypt()
            elif choice == 3:
                exit()
            else:
                click.echo('Invalid choice. Please enter 1, 2, or 3.')
        except click.exceptions.Abort:
            # Handle KeyboardInterrupt (Ctrl+C) to gracefully exit the program
            click.echo('\nExiting...')
            sys.exit()  # Exit the program properly
