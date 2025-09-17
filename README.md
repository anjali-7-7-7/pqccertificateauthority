“This project was built by our team
only for SIH Internal.” - BLUE TEAM ( ANJALI TIWARI, ABDUL SHEBAAZ REHMAN, RIYAZ AHEMAD, K. SRAVYA, KAMAAL RAAJ, SAMEER 4th year svit)


Overview

The PQC Certificate Dashboard is a unified platform designed to demonstrate the generation and management of digital certificates secured with Post-Quantum Cryptography (PQC). It leverages the Dilithium3 algorithm to create certificates resilient to quantum computing threats, with a simple, intuitive web interface.

Features

    PQC Keypair Generation: Generate master public and secret keys using the Dilithium3 algorithm.

    Certificate Creation: Mint certificates for various use cases (e.g., UPI, Cloud/TLS, Blockchain).

    Digital Signing: Sign certificate data with the PQC secret key for authenticity.

    History & Storage: Securely store and retrieve certificate data from a Firestore database.

    User-Friendly UI: Built with Streamlit for a seamless user experience.

Tech Stack

    Frontend: Streamlit (Python)

    Core Cryptography: Liboqs (C library for PQC algorithms)

    PQC Algorithm: Dilithium3 (part of the CRYSTALS family, a NIST standard)

    Binding: ctypes (Python's foreign function library)

    Database: Firebase Firestore (Serverless NoSQL)

Installation

To run this project locally, follow these steps:

    Clone the repository:
    Bash

git clone [Your-Repo-URL]
cd [Your-Repo-Name]

Install Python dependencies:
Bash

pip install -r requirements.txt

(Note: The requirements.txt file should include streamlit, firebase-admin, and any other necessary libraries.)

Install Liboqs:

    This project requires the liboqs shared library to be installed on your system.

    On Ubuntu/Debian:
    Bash

sudo apt-get install liboqs-dev

On macOS (with Homebrew):
Bash

        brew install liboqs

        For other operating systems, refer to the official liboqs installation guide.

    Set up Firebase:

        Create a new project in the Firebase Console.

        Go to Project settings > Service accounts and generate a new private key.

        Copy the JSON content of the private key file into your Python script as shown in the provided code.

▶ Usage

    Run the Streamlit application:
    Bash

    streamlit run app.py

    (Assuming your main script is named app.py)

    Open the dashboard in your web browser at http://localhost:8501.

    Generate Keys: Click the "Generate New PQC Keypair" button to create your master CA keys.

        Public Key: Used for verification.

        Secret Key: Used for signing (keep this secure!).

    Create a Certificate:

        Select a Use Case from the dropdown menu (e.g., UPI Payments).

        Fill in the required details in the form.

        Click "Create PQC Certificate". The application will sign the data and store it in Firestore.

    View History: The "Certificate History" section automatically updates with the latest certificates from the database. Expand each entry to see the full JSON data.

