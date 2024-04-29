import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def load_rsa_public_key_from_dns(domain, selector):
    query = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(query, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.startswith(b"k=rsa; p="):  # Check if the string contains the public key
                    # Extract the public key part after 'p='
                    public_key_str = txt_string.split(b"k=rsa; p=")[1]
                    
                    # Convert the base64-encoded key to PEM format
                    pem_public_key = b"-----BEGIN PUBLIC KEY-----\n" + \
                                     public_key_str + \
                                     b"\n-----END PUBLIC KEY-----"
                    return pem_public_key
    except dns.resolver.NoAnswer:
        pass
    return None

def check_rsa_key_pair(public_key_bytes, private_key_bytes):
    # Load private key from file
    try:
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except ValueError as e:
        return False, f"Error loading private key: {e}"

    # Load public key from bytes
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except ValueError as e:
        return False, f"Error loading public key: {e}"
    
    # Verify that keys are RSA keys
    if not isinstance(public_key, rsa.RSAPublicKey) or not isinstance(private_key, rsa.RSAPrivateKey):
        return False, "One of the keys is not an RSA key."
    
    # Check if private key matches public key
    return private_key.public_key() == public_key, ""

# Example usage:
if __name__ == "__main__":
    domain = "efscaph.com"  # Your domain here
    selector = "oyquhdrsks"  # Your selector here

    # Load public key from DNS
    public_key_str = load_rsa_public_key_from_dns(domain, selector)
    if public_key_str is None:
        print("Failed to retrieve public key from DNS.")
        exit(1)

    # Convert the public key string to bytes
    public_key_bytes = public_key_str

    # Load private key from file
    with open("private_key.pem", "rb") as private_key_file:
        private_key_bytes = private_key_file.read()
    
    # Check the key pair
    matched, error = check_rsa_key_pair(public_key_bytes, private_key_bytes)
    if matched:
        print("The RSA key pair is valid and matched.")
    else:
        print("The RSA key pair is not valid or not matched:", error)
