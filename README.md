# FastCrypt

FastCrypt is a command-line tool for encrypting and decrypting files securely using GitHub authentication. It also supports integration with Google Cloud Secret Manager for managing encryption keys.

## Features

- Encrypt files using AES encryption algorithm.
- Decrypt encrypted files with the appropriate key.
- Integration with GitHub authentication for secure access.
- Support for Google Cloud Secret Manager for key management.

## Installation

You can install FastCrypt via pip:

pip install fast-crypt

shell
Copy code

## Usage

### Encrypt a File

fast_crypt encrypt <file_path>

mathematica
Copy code

### Decrypt a File

fast_crypt decrypt <file_path>

arduino
Copy code

For more options and commands, run:

fast_crypt --help

markdown
Copy code

## Configuration

Before using FastCrypt, you need to set up GitHub authentication. You can do this by following the steps in the [GitHub Authentication Guide](#github-authentication).

## GitHub Authentication

FastCrypt uses GitHub OAuth for authentication. To set up authentication:

1. Create a GitHub OAuth app.
2. Set the `CLIENT_ID` and `CLIENT_SECRET` environment variables with your app's credentials.

## Contributing

Contributions are welcome! If you'd like to contribute to FastCrypt, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/my-feature`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature/my-feature`).
6. Create a new pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for d
