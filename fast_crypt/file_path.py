import os

import click


def file_path_prompt(action):
    if action == "encrypt":
        prompt_message = "Enter the path to the file you want to encrypt (Enter 0 to cancel): "
    elif action == "decrypt":
        prompt_message = "Enter the path to the file you want to decrypt (Enter 0 to cancel): "
    else:
        return None
    while True:
        file_path_input = input(prompt_message)
        if file_path_input == "0":
            return None  # User chose to exit
        file_path = does_exist(file_path_input, action)
        if file_path:
            return file_path


def does_exist(file_path, action):
    if os.path.exists(file_path):
        if action == 'decrypt' and file_path.endswith(".enc"):
            file_path = file_path[:-4]
            return file_path
        elif action == 'decrypt':
            click.echo("The file you want to decrypt should end with .enc")    
            return None    
        else:
            if file_path.endswith(".enc"):
                click.echo("The file is already encrypted")
            else:
                return file_path 
    else:
        click.echo("The file does not exist") 
        return None