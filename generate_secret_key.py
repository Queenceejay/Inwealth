import secrets

# Generate a secret key of 24 bytes (192 bits)
secret_key = secrets.token_hex(24)

# Write the secret key to a .env file
with open('.env', 'w') as f:
    f.write(f"SECRET_KEY={secret_key}\n")

print(f"Generated secret key: {secret_key}")
