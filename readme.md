# SFDS - Selective File Disclosure System

## Demo usage

- Create a folder called 'example' in issuer and add files and subdirectories for testing. Run issuer.py
- Copy 'disclosure.txt' from issuer to presenter and run presenter.py. Choose which files to be selectively disclosed.
- Copy 'presentation.txt' from presenter and 'jwt.txt', 'issuer_pub.json' from issuer to verifier. Run verifier.py
- The verifier is successfully able to access only the files allowed by presenter.
