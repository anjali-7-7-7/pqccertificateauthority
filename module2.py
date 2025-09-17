from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import ctypes
import ctypes.util
from ctypes import c_void_p, c_size_t, c_uint8, POINTER, byref, c_int, c_char_p
import json
import base64

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

except Exception as e:
    print(f"Failed to load liboqs: {e}")
    exit(1)

# --- Firebase Admin SDK credentials and Initialization (Integrated here) ---
firebase_service_account_config = {
    "type": "service_account",
    "project_id": "mvpy-88d89",
    "private_key_id": "4de4c080f397b042c366783c0913d59bc39654c0",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCe3Lnqw85UpTch\n55YyyHHk9zLuYfE/tpgNZCSXrke2tgVKNUqp21wUMiIjg4taKBcPH6rHxWIvbgZ/\naxNjTsZTLjv9G5tt74K4A5T0TMW2Gqnpr7HjHZL3l7jLLNrqPtk9HjsxEYT294Y9\nObkQt7dMCN5PDstwQ0CNqCHoWkfUaBBeKR9BeD3toDr+zL3NryPQhfwW3x3jYiHA\nUheBTo5X3TbJY9ckXcMKCMZ/6WKNBnf7zTNvlsoEBy22OB37QF1fXgT3lyztxmrU\n74OBDDwST7O99YQ3WT+oNhn61W3MXkNHrWhTcat5SzoEuEBVZOOMPzhT1XYMDE7O\nxlZ2iwdJAgMBAAECggEAANUlSDn0/aGeRcILhk5rcVFmbmCuYUH4jzu3JmGr0b2x\nhMARQJdNXP329xv0Iv+7cdJxfkrj1GexRq3z95RVes0p+3CFnuzJOFos6kai9kCf\nBdrE5faxY78AzZySFzqzmJSA7JGpfq6O7U2kx4chvLSlRSthWp22sc2F9QxaZA+S\ncxbyyn9XV4w5UNr++IvHPVhhCDnO/ZFdyx0tBVa2zHPgeV2WApikuFsMx2N2EdVZ\n2cTp3DPsd56EmW++H+WgCnCbC+fvD2LdHJW1QQoSlirykxVT3lPKudSjp+HbJjiM\n1uZQzmMaBfRrRzz+bk8qEiwiLdfnlxdzjtzh3oJ1IQKBgQDOWtOfT6LfdovXOYPY\nScVyYdKWOp3hUCfM5Nf6W/Ww44ZZVkL2XOERBk5YFSz3ylopm6+il5T7VmhGAgGk\nvP9Sc4fIWQPS11uWsd8k0Qn5Zs1ypJlj7NTDmf9/g61DfHPjyTBl5279tbSch7QL\nj3B/uxpFT9CMppn/snUEhRCPGQKBgQDFFOHADZkeViafXXRBBztHMN2+IVfvtsBK\nNVL/y6m+W1dHKRjjDSUsEwGqeYVH5fK61+KPp0dS+1+XZud31bXF8iJwz6qGWkwh\nEkVr4DI9N19cAfDwCAlh8zIn7fQZV4y0nJJ4VLdtGEu5XP6a2wn+LM75/6vW1oQ2\nxLsRPTavsQKBgGZ5QjgN0wMHmqAxpqCk2dFYdLw3talrJaihSAPC4PqLsm7w4GX5\nb6cFq6ggM+mFakrZTln+znQVz8hcPLazSFOInbhHRBfS7F+kSvy8diiM/Z9dz/KI\nbIwKEJAhMsydo+tNQKSKTlrdfihxV16aR7KWlpAu95CxNy58T5IEBloZAoGACvno\nwMuBFaFysTmBOgXvFT3xe59byGwDNZ7WqoxrPcDUkZAGZM7cnSHJ2/a8p451AFb5\ntUp5vHNnlYUTqybp4sZjiKjoNGdfChB8cU+hPKuS0gsBojywWRY0WujzyV2I5p45\nwh3lwVuzC/XT8Ef2vIM+W8oThfmYj3xRdtpT62ECgYEAj5zZbOPrOvou9gESOxoD\nbDWNmDG5+tEmZXnYaWZMoRrmGQ3ywUrREYKPg5SjvaaDmksjgBYULcBd1sqxTJG0\n6uPYqgNrjGeWJioWqcwtMweCPcstXXaYYGEGdIEfyZ0wljVB/ayqfVD/IOyXETox\nwjQiX3d5M0O/MwBnDsilMtw=\n-----END PRIVATE KEY-----",
    "client_email": "firebase-adminsdk-fbsvc@mvpy-88d89.iam.gserviceaccount.com",
    "client_id": "118236180553188787159",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40mvpy-88d89.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(firebase_service_account_config)
        firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Error initializing Firebase Admin SDK: {e}")
    raise HTTPException(status_code=500, detail="Firebase initialization failed.")

# --- PQC Logic using ctypes-loaded liboqs ---
def generate_dilithium_keypair() -> tuple[str, str]:
    sig_name = "Dilithium3"
    sig_name_bytes = sig_name.encode('utf-8')
    sig_ptr = liboqs.OQS_SIG_new(sig_name_bytes)
    if not sig_ptr:
        return None, None
    try:
        sig = sig_ptr.contents
        public_key = (c_uint8 * sig.len_public_key)()
        secret_key = (c_uint8 * sig.len_secret_key)()
        if liboqs.OQS_SIG_keypair(sig_ptr, public_key, secret_key) != 0:
            return None, None
        return bytes(public_key).hex(), bytes(secret_key).hex()
    finally:
        liboqs.OQS_SIG_free(sig_ptr)

def sign_certificate_data(data: dict, secret_key_hex: str) -> str:
    sig_name = "Dilithium3"
    sig_name_bytes = sig_name.encode('utf-8')
    sig_ptr = liboqs.OQS_SIG_new(sig_name_bytes)
    if not sig_ptr:
        return None
    try:
        sig = sig_ptr.contents
        secret_key_bytes = bytes.fromhex(secret_key_hex)
        secret_key_buffer = (c_uint8 * len(secret_key_bytes)).from_buffer_copy(secret_key_bytes)
        data_string = json.dumps(data, sort_keys=True).encode('utf-8')
        data_buffer = (c_uint8 * len(data_string)).from_buffer_copy(data_string)
        signature_len = c_size_t(sig.len_signature)
        signature = (c_uint8 * sig.len_signature)()
        if liboqs.OQS_SIG_sign(
            sig_ptr, signature, byref(signature_len),
            data_buffer, len(data_string),
            secret_key_buffer
        ) != 0:
            return None
        return bytes(signature).hex()
    finally:
        liboqs.OQS_SIG_free(sig_ptr)

# --- FastAPI App Initialization ---
app = FastAPI(
    title="PQC Certificate API",
    description="An API to generate quantum-secure digital certificates using Dilithium3."
)

# --- Pydantic models for API request and response data ---
class KeypairResponse(BaseModel):
    public_key: str = Field(..., description="The public key for Dilithium3.")
    secret_key: str = Field(..., description="The secret key for Dilithium3.")
    message: str

class CertificateRequest(BaseModel):
    use_case: str = Field(..., description="The specific use case for the certificate (e.g., 'academic_transcript').")
    data: dict = Field(..., description="A dictionary containing the details of the certificate data to be signed.")
    public_key: str = Field(..., description="The public key used for verification.")
    secret_key: str = Field(..., description="The secret key used for signing.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "use_case": "academic_transcript",
                    "data": {
                        "student_id": "ST12345",
                        "course": "Quantum Cryptography",
                        "grade": "A+",
                        "university": "State University"
                    },
                    "public_key": "Paste the public key from the /generate-keypair endpoint here.",
                    "secret_key": "Paste the secret key from the /generate-keypair endpoint here."
                }
            ]
        }
    }

class CertificateResponse(BaseModel):
    use_case: str
    pqc_signature: str
    timestamp: str
    details: dict

# --- API Endpoints ---
@app.get(
    "/api/v1/generate-keypair",
    response_model=KeypairResponse,
    tags=["PQC Certificates"],
    summary="Generate a New PQC Keypair",
    description="""
    This endpoint generates a new pair of quantum-secure keys (Dilithium3).

    1. Call this endpoint first to get a fresh `public_key` and `secret_key`.
    2. Use these keys in the request body of the `/api/v1/create-certificate` endpoint.
    """
)
def generate_keypair_endpoint():
    try:
        public_key, secret_key = generate_dilithium_keypair()
        if public_key and secret_key:
            return {
                "public_key": public_key,
                "secret_key": secret_key,
                "message": "New PQC keypair generated successfully."
            }
        raise HTTPException(status_code=500, detail="Failed to generate keypair.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.post(
    "/api/v1/create-certificate",
    response_model=CertificateResponse,
    tags=["PQC Certificates"],
    summary="Create and Sign a PQC Certificate",
    description="""
    This endpoint creates a certificate for a given use case, signs it with the provided secret key, and stores it in the database.

    1. **First, use the `/api/v1/generate-keypair` endpoint.** You need the public and secret keys from there.
    2. **Copy the `public_key` and `secret_key`** from the response.
    3. **Paste the keys into the example body below.**
    4. **Fill out the rest of the form** and click 'Execute' to sign and save your certificate.
    """
)
def create_certificate_endpoint(request: CertificateRequest):
    try:
        certificate_data = {
            'use_case': request.use_case,
            'timestamp': datetime.now().isoformat(),
            'public_key': request.public_key,
            **request.data
        }
        pqc_signature = sign_certificate_data(certificate_data, request.secret_key)
        if not pqc_signature:
            raise HTTPException(status_code=500, detail="Failed to sign the data.")
        full_certificate = {
            **certificate_data,
            'pqc_signature': pqc_signature
        }
        db.collection('pqc_certificates').add(full_certificate)
        details = {k: v for k, v in full_certificate.items() if k not in ['use_case', 'pqc_signature', 'timestamp', 'public_key']}
        return {
            "use_case": full_certificate['use_case'],
            "pqc_signature": full_certificate['pqc_signature'],
            "timestamp": full_certificate['timestamp'],
            "details": details
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@app.get(
    "/api/v1/history",
    tags=["Utility"],
    summary="Retrieve the Last 10 Certificates",
    description="Fetches and returns a list of the 10 most recently created certificates from the database."
)
def get_history():
    try:
        certificates_ref = db.collection('pqc_certificates').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(10)
        docs = certificates_ref.stream()
        history = [doc.to_dict() for doc in docs]
        return {"history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch history: {str(e)}")
