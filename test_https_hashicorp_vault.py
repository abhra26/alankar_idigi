import os
import base64
import json
import requests
import urllib3
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from params import *

# Disable warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Vault API headers
HEADERS = {
    "X-Vault-Token": VAULT_TOKEN,
    "Content-Type": "application/json"
}

def get_wrapping_key():
    """
    Retrieve the transit wrapping key from Vault.
    Returns:
      A PEM-encoded public key (string) used for wrapping the ephemeral key.
    """
    url = f"{VAULT_ADDR}/v1/transit/wrapping_key"
    response = requests.get(url, headers=HEADERS, verify=VAULT_CACERT)
    if response.status_code == 200:
        data = response.json()
        public_key_pem = data["data"]["public_key"]
        print("Retrieved Vault transit wrapping key.")
        return public_key_pem
    else:
        raise Exception(f"Failed to retrieve wrapping key: {response.text}")

def wrap_import_key_material(target_key: bytes, wrapping_key_pem: str) -> str:
    """
    Wrap external key material for import into Vault.
    
    Steps:
      1. Generate an ephemeral 256-bit AES key.
      2. Wrap the target key material using AES-KWP with padding (using the ephemeral key).
      3. Load the Vault wrapping key (PEM) and wrap the ephemeral key using RSA OAEP (SHA-256).
      4. Concatenate the RSA-wrapped ephemeral key (first 512 bytes) and the AES-wrapped key material.
      5. Base64-encode the resulting ciphertext.
      
    Returns:
      A base64-encoded string containing the wrapped key material.
    """
    # 1. Generate an ephemeral AES-256 key (32 bytes)
    ephemeral_key = os.urandom(32)
    
    # 2. Wrap the target key using AES-KWP with padding.
    #    The target key (the key you want to import) is provided as raw bytes.
    wrapped_target_key = aes_key_wrap_with_padding(ephemeral_key, target_key)
    
    # 3. Load the Vault-provided wrapping key (PEM) and wrap the ephemeral key using RSA OAEP with SHA-256.
    public_key = serialization.load_pem_public_key(wrapping_key_pem.encode())
    wrapped_ephemeral = public_key.encrypt(
        ephemeral_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. Concatenate: first the RSA-wrapped ephemeral key, then the AES-wrapped target key.
    final_ciphertext = wrapped_ephemeral + wrapped_target_key
    
    # 5. Base64-encode the final ciphertext.
    b64_ciphertext = base64.b64encode(final_ciphertext).decode()
    return b64_ciphertext

def import_key(key_name: str, wrapped_key_material: str):
    """
    Imports the externally generated key material into Vault's Transit engine.
    
    The payload includes:
      - type: set to "aes256-gcm96"
      - version: the new key version (1 for a new key)
      - ciphertext: the base64-encoded wrapped key material.
    """
    url = f"{VAULT_ADDR}/v1/transit/keys/{key_name}/import"
    data = {
        "type": "aes256-gcm96",
        "version": 1,
        "ciphertext": wrapped_key_material
    }
    response = requests.post(url, json=data, headers=HEADERS, verify=VAULT_CACERT)
    if response.status_code in [200, 204]:
        print(f"✅ Key '{key_name}' imported successfully.")
    else:
        print(f"❌ Key import failed: {response.text}")

def encrypt_data(key_name: str, plaintext: str) -> str:
    """
    Encrypt data using Vault's Transit engine for the given key.
    """
    url = f"{VAULT_ADDR}/v1/transit/encrypt/{key_name}"
    encoded_text = base64.b64encode(plaintext.encode()).decode()
    data = {"plaintext": encoded_text}
    response = requests.post(url, json=data, headers=HEADERS, verify=VAULT_CACERT)
    if response.status_code == 200:
        ciphertext = response.json()["data"]["ciphertext"]
        print(f"Encrypted Data: {ciphertext}")
        return ciphertext
    else:
        print(f"Encryption failed: {response.text}")
        return ""

def decrypt_data(key_name: str, ciphertext: str):
    """
    Decrypt data using Vault's Transit engine for the given key.
    """
    url = f"{VAULT_ADDR}/v1/transit/decrypt/{key_name}"
    data = {"ciphertext": ciphertext}
    response = requests.post(url, json=data, headers=HEADERS, verify=VAULT_CACERT)
    if response.status_code == 200:
        decoded_text = base64.b64decode(response.json()["data"]["plaintext"]).decode()
        print(f"Decrypted Data: {decoded_text}")
    else:
        print(f"Decryption failed: {response.text}")

# Load client credentials from YAML file
def load_yaml_data(filename=LICENSE_FILE_PATH):
    with open(filename, "r") as file:
        return yaml.safe_load(file)

# Function to validate license and obtain access token
def get_access_token():
    client_data = load_yaml_data()
    client_info = client_data["client"]

    url = f"{BASE_URL}/v1/license/validate"
    payload = {
        "client_id": client_info["client_id"],
        "license_key": client_info["license_key"]
    }

    headers = {"Content-Type": "application/json"}

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 200:
        resp = response.json()
        access_token = resp.get("access_token")
        print(f"✅ License Validated.\n")
        print(f"Access Token:")
        print(" ".join(f"{byte:02X}" for byte in base64.b64decode(access_token.encode())))
        return access_token
    else:
        print(f"❌ License validation failed: {response.json().get('detail')}")
        return None
    
# Function to send API requests
def send_request(endpoint, payload=None, method="GET"):
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == "POST":
            response = requests.post(url, headers=HEADERS_QTRNG, json=payload)
        else:
            response = requests.get(url, headers=HEADERS_QTRNG)

        response_data = response.json()
        print(f"✅ Response from {endpoint}:\n{json.dumps(response_data, indent=4)}\n")
        return response_data
    except requests.exceptions.RequestException as e:
        print(f"❌ Error calling {endpoint}: {e}")
        return {}
    
def hex_strings_to_bytes(hex_strings):
    """
    Converts a list of space-separated hex strings back to bytes.
    
    :param hex_strings: List of strings where each string contains space-separated hex values
    :return: List of byte sequences
    """
    return [bytes.fromhex(hex_string) for hex_string in hex_strings]


def derive_key_hkdf_sha3_256(entropy: bytes, salt: bytes, info: bytes = b"", length: int = 32) -> bytes:
    """
    Derives a key using HKDF with SHA3-256.

    :param entropy: 32-byte input key material (IKM)
    :param salt: Optional salt value (recommended 16–32 bytes)
    :param info: Optional context-specific information (domain separation)
    :param length: Length of the derived key (default: 32 bytes)
    :return: Derived key of specified length
    """
    if len(entropy) != 32:
        raise ValueError("Entropy must be exactly 32 bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(entropy)

if __name__ == "__main__":
    # For demonstration, we use a randomly generated 32-byte key as the target key material.
    # In a real scenario, this would be your externally generated key material.

    # Obtain a valid access token
    access_token = get_access_token()
    if not access_token:
        print("❌ No valid access token. Exiting test.")
        exit(1)

    HEADERS_QTRNG = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    entropy_payload = {"block_size": 32, "block_count": 5, "entropy_type": "default"}
    response = send_request("/v1/entropy", entropy_payload, method="POST")
    entropy_list = hex_strings_to_bytes(response["entropy"])
    info = b"Quantum-Safe KDF"

    target_key = derive_key_hkdf_sha3_256(
        entropy=entropy_list[2],
        salt=entropy_list[1][:16],
        info=info,
        length=32
    )

    print("Target Key (hex):", target_key.hex())
    
    # Retrieve the wrapping key from Vault
    wrapping_key_pem = get_wrapping_key()
    print("Vault Wrapping Key (PEM):\n", wrapping_key_pem)
    
    # Wrap the target key material
    wrapped_key_material = wrap_import_key_material(target_key, wrapping_key_pem)
    print("Wrapped Key Material (base64):\n", wrapped_key_material)
    
    # Get a key name from the user (or set a name)
    key_name = input("Enter a name for your key: ")
    
    # Import the wrapped key material into Vault
    import_key(key_name, wrapped_key_material)
    
    # Optionally, test encryption/decryption
    user_data = input("Enter data to encrypt: ")
    ciphertext = encrypt_data(key_name, user_data)
    if ciphertext:
        decrypt_data(key_name, ciphertext)
