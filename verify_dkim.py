import sys
import dkim

def verify_dkim(email_file):
    with open(email_file, 'rb') as f:
        message = f.read()

    try:
        result = dkim.verify(message)
        if result:
            print("DKIM signature is valid.")
        else:
            print("DKIM signature is not valid.")
            if hasattr(result, 'details'):
                print("DKIM verification results:")
                for key, value in result.details.items():
                    print(f"{key}: {value}")
    except dkim.ValidationError as e:
        print("DKIM validation error:", e)

if __name__ == "__main__":

    email_file = 'signed_email.txt'
    verify_dkim(email_file)