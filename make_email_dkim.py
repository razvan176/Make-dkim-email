import dkim
from email.mime.text import MIMEText
import email.parser

def sign_email():
    """
    This function signs an email using a DKIM signature.

    The function reads an email from 'email.txt', parses its content, and signs it using a DKIM signature.
    The private key used for signing is loaded from 'private_key.pem'. The signed email is then written
    to 'signed_email.txt'.
    The public key is located in oyquhdrsks._domainkey.efscaph.com in cloudflare.
    Can u check if the public key is with :
    dig oyquhdrsks._domainkey.efscaph.com
    The function automatically includes all headers present in the email for the DKIM signature.
    """
    with open('email.txt', 'r') as f:
        email_content = f.read()

    msg = email.parser.Parser().parsestr(email_content)

    # Load the private key
    with open("private_key.pem", "rb") as key_file:
        private_key = key_file.read()

    # Specify the domain and selector
    domain = "efscaph.com"
    selector = "oyquhdrsks"

    try:
        # Create a DKIM signature
        dkim_signature = dkim.sign(
            message=msg.as_bytes(),
            selector=selector.encode(),
            domain=domain.encode(),
            privkey=private_key,
            include_headers=msg.keys()  # Include all headers present in the email
        )

        msg['DKIM-Signature'] = dkim_signature.decode().split(' ', 1)[1]

        # Write the email to a new file
        with open('signed_email.txt', 'w') as file:
            file.write(msg.as_string())

    except Exception as e:
        print("Email signing failed:", e)

if __name__ == "__main__":
    sign_email()
