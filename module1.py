import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import ctypes
import ctypes.util
from ctypes import c_void_p, c_size_t, c_uint8, POINTER, byref, c_int, c_char_p
import json
import base64
import random

# --- Custom Styling (CSS) for a professional purple theme ---
st.markdown("""
<style>
/* Main background gradient and font color */
.stApp {
    background: linear-gradient(180deg, #2d1a3e 0%, #1a1129 100%); /* Dark Purple/Violet */
    color: #eae6f2; /* Light Lavender text */
}

/* Header colors */
h1, h2, h3 {
    color: #FFFFFF;
}

/* Card/Container styling */
[data-testid="stVerticalBlockBorderWrapper"] {
    background-color: #3b2a4e; /* Dark Violet */
    border-radius: 16px;
    border: 1px solid #4a3a5e;
    padding: 1.5rem;
}

/* Custom styling for the key display box */
.key-box {
    background-color: #1a1129; /* Darkest background color */
    border: 1px solid #3b2a4e;
    border-radius: 12px;
    padding: 10px;
    font-family: 'Consolas', 'Menlo', 'monospace';
    color: #E5E7EB;
    overflow-x: scroll;
    white-space: nowrap;
}

/* Custom HTML Copy Button */
.copy-btn {
    background-color: #8b5cf6; /* Vibrant Violet */
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px 16px;
    font-size: 14px;
    font-weight: bold;
    cursor: pointer;
    transition: background-color 0.2s;
    height: 52px;
}
.copy-btn:hover { background-color: #7c3aed; }
.copy-btn:active { background-color: #6d28d9; }

/* Form Submit Button styling */
.stForm [data-testid="stFormSubmitButton"] button {
    background-color: #8b5cf6; /* Vibrant Violet */
    border-radius: 8px;
    border: none;
    width: 100%;
}
.stForm [data-testid="stFormSubmitButton"] button:hover {
    background-color: #7c3aed;
}

/* Expander/Accordion styling */
.st-emotion-cache-1h9us21, .st-emotion-cache-1ftn52d {
    background-color: #4a3a5e;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)


# --- Load liboqs shared library using ctypes ---
try:
    # Load libc for memcmp
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    memcmp = libc.memcmp
    memcmp.restype = ctypes.c_int
    memcmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    liboqs_path = ctypes.util.find_library('oqs')
    if not liboqs_path:
        raise RuntimeError("liboqs shared library not found. Please install liboqs.")
    liboqs = ctypes.CDLL(liboqs_path)

    # --- Define the OQS_SIG struct from liboqs API for digital signatures ---
    class OQS_SIG(ctypes.Structure):
        _fields_ = [
            ('method_name', ctypes.c_char_p),
            ('alg_version', ctypes.c_char_p),
            ('claimed_nist_level', c_uint8),
            ('is_sig_deterministic', ctypes.c_bool),
            ('len_public_key', c_size_t),
            ('len_secret_key', c_size_t),
            ('len_signature', c_size_t)
        ]
    OQS_SIG_POINTER = ctypes.POINTER(OQS_SIG)

    # Define function prototypes for liboqs
    liboqs.OQS_SIG_new.restype = OQS_SIG_POINTER
    liboqs.OQS_SIG_new.argtypes = [c_char_p]

    liboqs.OQS_SIG_keypair.restype = c_int
    liboqs.OQS_SIG_keypair.argtypes = [OQS_SIG_POINTER, POINTER(c_uint8), POINTER(c_uint8)]

    liboqs.OQS_SIG_sign.restype = c_int
    liboqs.OQS_SIG_sign.argtypes = [OQS_SIG_POINTER, POINTER(c_uint8), POINTER(c_size_t), POINTER(c_uint8), c_size_t, POINTER(c_uint8)]

    liboqs.OQS_SIG_verify.restype = c_int
    liboqs.OQS_SIG_verify.argtypes = [OQS_SIG_POINTER, POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t]

    liboqs.OQS_SIG_free.restype = None
    liboqs.OQS_SIG_free.argtypes = [OQS_SIG_POINTER]

    st.success("liboqs loaded successfully using ctypes!")

except Exception as e:
    st.error(f"Failed to load liboqs using ctypes. Please ensure the library is installed. Error: {e}")
    st.stop()


# --- Firebase Admin SDK credentials, embedded directly in the script ---
firebase_service_account_config = {
    "type": "service_account",
    "project_id": "mvpy-88d89",
    "private_key_id": "4de4c080f397b042c366783c0913d59bc39654c0",
    "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCe3Lnqw85UpTch
55YyyHHk9zLuYfE/tpgNZCSXrke2tgVKNUqp21wUMiIjg4taKBcPH6rHxWIvbgZ/
axNjTsZTLjv9G5tt74K4A5T0TMW2Gqnpr7HjHZL3l7jLLNrqPtk9HjsxEYT294Y9
ObkQt7dMCN5PDstwQ0CNqCHoWkfUaBBeKR9BeD3toDr+zL3NryPQhfwW3x3jYiHA
UheBTo5X3TbJY9ckXcMKCMZ/6WKNBnf7zTNvlsoEBy22OB37QF1fXgT3lyztxmrU
74OBDDwST7O99YQ3WT+oNhn61W3MXkNHrWhTcat5SzoEuEBVZOOMPzhT1XYMDE7O
xlZ2iwdJAgMBAAECggEAANUlSDn0/aGeRcILhk5rcVFmbmCuYUH4jzu3JmGr0b2x
hMARQJdNXP329xv0Iv+7cdJxfkrj1GexRq3z95RVes0p+3CFnuzJOFos6kai9kCf
BdrE5faxY78AzZySFzqzmJSA7JGpfq6O7U2kx4chvLSlRSthWp22sc2F9QxaZA+S
cxbyyn9XV4w5UNr++IvHPVhhCDnO/ZFdyx0tBVa2zHPgeV2WApikuFsMx2N2EdVZ
2cTp3DPsd56EmW++H+WgCnCbC+fvD2LdHJW1QQoSlirykxVT3lPKudSjp+HbJjiM
1uZQzmMaBfRrRzz+bk8qEiwiLdfnlxdzjtzh3oJ1IQKBgQDOWtOfT6LfdovXOYPY
ScVyYdKWOp3hUCfM5Nf6W/Ww44ZZVkL2XOERBk5YFSz3ylopm6+il5T7VmhGAgGk
vP9Sc4fIWQPS11uWsd8k0Qn5Zs1ypJlj7NTDmf9/g61DfHPjyTBl5279tbSch7QL
j3B/uxpFT9CMppn/snUEhRCPGQKBgQDFFOHADZkeViafXXRBBztHMN2+IVfvtsBK
NVL/y6m+W1dHKRjjDSUsEwGqeYVH5fK61+KPp0dS+1+XZud31bXF8iJwz6qGWkwh
EkVr4DI9N19cAfDwCAlh8zIn7fQZV4y0nJJ4VLdtGEu5XP6a2wn+LM75/6vW1oQ2
xLsRPTavsQKBgGZ5QjgN0wMHmqAxpqCk2dFYdLw3talrJaihSAPC4PqLsm7w4GX5
b6cFq6ggM+mFakrZTln+znQVz8hcPLazSFOInbhHRBfS7F+kSvy8diiM/Z9dz/KI
bIwKEJAhMsydo+tNQKSKTlrdfihxV16aR7KWlpAu95CxNy58T5IEBloZAoGACvno
wMuBFaFysTmBOgXvFT3xe59byGwDNZ7WqoxrPcDUkZAGZM7cnSHJ2/a8p451AFb5
tUp5vHNnlYUTqybp4sZjiKjoNGdfChB8cU+hPKuS0gsBojywWRY0WujzyV2I5p45
wh3lwVuzC/XT8Ef2vIM+W8oThfmYj3xRdtpT62ECgYEAj5zZbOPrOvou9gESOxoD
bDWNmDG5+tEmZXnYaWZMoRrmGQ3ywUrREYKPg5SjvaaDmksjgBYULcBd1sqxTJG0
6uPYqgNrjGeWJioWqcwtMweCPcstXXaYYGEGdIEfyZ0wljVB/ayqfVD/IOyXETox
wjQiX3d5M0O/MwBnDsilMtw=
-----END PRIVATE KEY-----""",
    "client_email": "firebase-adminsdk-fbsvc@mvpy-88d89.iam.gserviceaccount.com",
    "client_id": "118236180553188787159",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40mvpy-88d89.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}
# --- Initialize Firebase ---
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(firebase_service_account_config)
        firebase_admin.initialize_app(cred)
    db = firestore.client()
    st.success("Firebase Admin SDK initialized successfully.")
except Exception as e:
    st.error(f"Error initializing Firebase Admin SDK: {e}")
    st.stop()


# --- PQC Logic using ctypes-loaded liboqs ---
# We'll use Dilithium3, a signature scheme, which is better suited for message signing.
def generate_dilithium_keypair():
    """Generates a Dilithium keypair and stores it in the session state."""
    st.session_state.sig_name = "Dilithium3"
    sig_name_bytes = st.session_state.sig_name.encode('utf-8')
    sig_ptr = liboqs.OQS_SIG_new(sig_name_bytes)
    
    if not sig_ptr:
        st.error(f"Failed to create SIG context for {st.session_state.sig_name}.")
        return None, None
        
    try:
        sig = sig_ptr.contents
        public_key = (c_uint8 * sig.len_public_key)()
        secret_key = (c_uint8 * sig.len_secret_key)()
        
        if liboqs.OQS_SIG_keypair(sig_ptr, public_key, secret_key) != 0:
            st.error("Failed to generate PQC keypair.")
            return None, None
            
        st.session_state.pqc_public_key = bytes(public_key).hex()
        st.session_state.pqc_secret_key = bytes(secret_key).hex()
        return bytes(public_key).hex(), bytes(secret_key).hex()
    finally:
        liboqs.OQS_SIG_free(sig_ptr)

def sign_certificate_data(data, secret_key_hex):
    """Signs the transaction data using the PQC secret key."""
    if not st.session_state.get('pqc_secret_key'):
        st.warning("Please generate a keypair first.")
        return None

    sig_name_bytes = st.session_state.sig_name.encode('utf-8')
    sig_ptr = liboqs.OQS_SIG_new(sig_name_bytes)
    if not sig_ptr:
        st.error(f"Failed to create SIG context for {st.session_state.sig_name}.")
        return None

    try:
        sig = sig_ptr.contents
        
        secret_key_bytes = bytes.fromhex(secret_key_hex)
        # Create a C-compatible buffer for the secret key
        secret_key_buffer = (c_uint8 * len(secret_key_bytes)).from_buffer_copy(secret_key_bytes)
        
        data_string = json.dumps(data, sort_keys=True).encode('utf-8')
        # Create a C-compatible buffer from the Python bytes object
        data_buffer = (c_uint8 * len(data_string)).from_buffer_copy(data_string)

        signature_len = c_size_t(sig.len_signature)
        signature = (c_uint8 * sig.len_signature)()
        
        if liboqs.OQS_SIG_sign(
            sig_ptr, signature, byref(signature_len),
            data_buffer, len(data_string), 
            secret_key_buffer # Pass the C-compatible secret key buffer
        ) != 0:
            st.error("Failed to sign the data.")
            return None
            
        return bytes(signature).hex()
    finally:
        liboqs.OQS_SIG_free(sig_ptr)

# --- Main App UI ---
st.set_page_config(page_title="PQC Certificate Platform", page_icon="🔒")

st.title("🔒 PQC Certificate Platform")
st.markdown("A unified platform to generate **quantum-secure digital certificates** for various use cases.")
st.divider()

# Initialize session state for keys
if 'pqc_public_key' not in st.session_state:
    st.session_state.pqc_public_key = None
    st.session_state.pqc_secret_key = None
    
# --- STEP 1: Key Generation ---
with st.container(border=True):
    st.header("Step 1: Generate Your PQC Keys")
    st.markdown("Click the button below to generate a unique **public** and **secret** keypair. These keys are essential for creating and verifying certificates. Keep your secret key safe!")

    if st.button("Generate New PQC Keypair"):
        with st.spinner('Generating keypair...'):
            generate_dilithium_keypair()
        st.success("New PQC keypair generated for your session.")

    # Use st.expander to hide long keys unless the user wants to see them
    with st.expander("Show Generated Keys"):
        st.code(f"Public Key: {st.session_state.pqc_public_key}")
        st.code(f"Secret Key: {st.session_state.pqc_secret_key}")

st.markdown("---")

# --- STEP 2: Certificate Creation ---
with st.container(border=True):
    st.header("Step 2: Create a PQC Certificate")
    st.markdown("Select a use case and enter the relevant details. The platform will use your generated keys to create a quantum-secure digital certificate.")

    use_case = st.selectbox(
        "Select a Use Case:",
        ("UPI Payments", "Cloud TLS", "Blockchain/Web3")
    )

    # --- Dynamic form based on the selected use case ---
    if use_case == "UPI Payments":
        st.markdown("#### UPI Payments Details")
        st.markdown("Enter simulated UPI transaction details to generate a certificate.")
        transaction_id = st.text_input("UPI Transaction ID", "UPIC" + str(random.randint(100000000, 999999999)))
        amount = st.number_input("Amount (₹)", min_value=1.00, value=500.00, format="%.2f")
        upi_id = st.text_input("Sender's UPI ID", "sender_name@bank")
    
        certificate_data = {
            'use_case': 'upi',
            'transaction_id': transaction_id,
            'amount': amount,
            'upi_id': upi_id,
            'timestamp': datetime.now().isoformat(),
            'public_key': st.session_state.pqc_public_key
        }

    elif use_case == "Cloud TLS":
        st.markdown("#### Cloud TLS Details")
        st.markdown("Enter domain and server details to generate a quantum-safe TLS certificate.")
        domain_name = st.text_input("Domain Name", "example.com")
        server_id = st.text_input("Server ID", "server_12345")
        csr_data = st.text_area("Certificate Signing Request (CSR)", "---BEGIN CSR---...", height=100)
    
        certificate_data = {
            'use_case': 'cloud_tls',
            'domain_name': domain_name,
            'server_id': server_id,
            'csr_data': csr_data,
            'timestamp': datetime.now().isoformat(),
            'public_key': st.session_state.pqc_public_key
        }

    elif use_case == "Blockchain/Web3":
        st.markdown("#### Blockchain/Web3 Details")
        st.markdown("Enter transaction details to generate a PQC signature for a blockchain transaction.")
        wallet_address = st.text_input("Sender's Wallet Address", "0x" + "a" * 40)
        transaction_hash = st.text_input("Transaction Hash", "0x" + "b" * 64)
        dapp_name = st.text_input("dApp Name", "Decentralized Finance App")
    
        certificate_data = {
            'use_case': 'blockchain',
            'wallet_address': wallet_address,
            'transaction_hash': transaction_hash,
            'dapp_name': dapp_name,
            'timestamp': datetime.now().isoformat(),
            'public_key': st.session_state.pqc_public_key
        }

    if st.button("Create PQC Certificate"):
        if not st.session_state.pqc_secret_key:
            st.error("🚨 Please generate a PQC keypair first.")
        else:
            try:
                pqc_signature = sign_certificate_data(certificate_data, st.session_state.pqc_secret_key)
                
                if pqc_signature:
                    full_certificate = {
                        **certificate_data,
                        'pqc_signature': pqc_signature
                    }
                    
                    db.collection('pqc_certificates').add(full_certificate)
                    st.success("✅ PQC Certificate created and saved successfully!")
                    
                    with st.expander("View the Generated Certificate"):
                        st.json(full_certificate)
            except Exception as e:
                st.error(f"An error occurred during certificate generation: {e}")

st.markdown("---")

# --- STEP 3: View History ---
with st.container(border=True):
    st.header("Step 3: View Certificate History")
    st.markdown("Below are the most recent certificates securely stored in your Firestore database.")

    try:
        certificates_ref = db.collection('pqc_certificates').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(10)
        docs = certificates_ref.stream()
        
        certificate_list = list(docs)
        if not certificate_list:
            st.info("No certificates found. Create one above!")
        else:
            for doc in certificate_list:
                certificate = doc.to_dict()
                with st.expander(f"Certificate ID: {doc.id} - Use Case: {certificate.get('use_case', 'N/A')}"):
                    st.json(certificate)
    except Exception as e:
        st.error(f"Failed to fetch certificate history: {e}")
