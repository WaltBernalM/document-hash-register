import re
from typing import Dict, List, Any
from cryptography.x509 import load_pem_x509_certificate, Certificate 
from hashlib import sha256
from ccf.receipt import root, verify, check_endorsements
from cffi import VerificationError
from OpenSSL.crypto import (
  X509,
  X509Store,
  X509StoreContext, 
)


def verify_receipt(receipt: Dict[str, Any], service_cert_pem: str) -> None:
  """Function to verify that a given write transaction receipt is valid based
  on its content and the service certificate.
  Throws an exception if the verification fails.""" 

  try:
    # Check that all the fields are present in the receipt 
    assert "cert" in receipt 
    assert "leafComponents" in receipt 
    assert "claimsDigest" in receipt["leafComponents"] 
    assert "commitEvidence" in receipt["leafComponents"] 
    assert "writeSetDigest" in receipt["leafComponents"] 
    assert "proof" in receipt 
    assert "signature" in receipt 

    # Set the variables 
    node_cert_pem = receipt["cert"] 
    claims_digest_hex = receipt["leafComponents"]["claimsDigest"] 
    commit_evidence_str = receipt["leafComponents"]["commitEvidence"] 

    write_set_digest_hex = receipt["leafComponents"]["writeSetDigest"] 
    proof_list = receipt["proof"]
    service_endorsements_certs_pem = receipt.get("serviceEndorsements", [])
    root_node_signature = receipt["signature"] 
    
    # Load service and node PEM certificates
    service_cert = load_pem_x509_certificate(service_cert_pem.encode()) 
    node_cert = load_pem_x509_certificate(node_cert_pem.encode()) 

    # Load service endorsements PEM certificates
    service_endorsements_certs = [
      load_pem_x509_certificate(pem.encode())
      for pem in service_endorsements_certs_pem
    ] 

    # Compute leaf of the Merkle Tree 
    leaf_node_hex = compute_leaf_node(
      claims_digest_hex, commit_evidence_str, write_set_digest_hex
    ) 
    
    # Compute root of the Merkle Tree
    root_node = root(leaf_node_hex, proof_list) 

    # Verify signature of the signing node over the root of the tree
    verify(root_node, root_node_signature, node_cert) 

    # Verify node certificate is endorsed by the service certificates through endorsements
    check_endorsements(node_cert, service_cert, service_endorsements_certs) 

    # Alternative: Verify node certificate is endorsed by the service certificates through endorsements 
    verify_openssl_certificate(node_cert, service_cert, service_endorsements_certs)
  except Exception as e:
    raise VerificationError("Receipt verification failed") from e

def compute_leaf_node(
  claims_digest_hex: str, commit_evidence_str: str, write_set_digest_hex: str 
) -> str:
  """Function to compute the leaf node associated to a transaction 
  given its claims digest, commit evidence, and write set digest.""" 

  # Digest commit evidence string
  commit_evidence_digest = sha256(commit_evidence_str.encode()).digest() 

  # Convert write set digest to bytes
  write_set_digest = bytes.fromhex(write_set_digest_hex) 

  # Convert claims digest to bytes
  claims_digest = bytes.fromhex(claims_digest_hex) 

  # Create leaf node by hashing the concatenation of its three components 
  # as bytes objects in the following order: 
  # 1. write_set_digest 
  # 2. commit_evidence_digest 
  # 3. claims_digest 
  leaf_node_digest = sha256( 
    write_set_digest + commit_evidence_digest + claims_digest 
  ).digest() 

  # Convert the result into a string of hexadecimal digits 
  return leaf_node_digest.hex() 

def verify_openssl_certificate( 
  node_cert: Certificate, 
  service_cert: Certificate, 
  service_endorsements_certs: List[Certificate], 
) -> None: 
  """Verify that the given node certificate is a valid OpenSSL certificate through 
  the service certificate and a list of endorsements certificates.""" 

  try: 
    store = X509Store() 

    # pyopenssl does not support X509_V_FLAG_NO_CHECK_TIME. For recovery of expired 
    # services and historical receipts, we want to ignore the validity time. 0x200000 
    # is the bitmask for this option in more recent versions of OpenSSL. 
    X509_V_FLAG_NO_CHECK_TIME = 0x200000 
    store.set_flags(X509_V_FLAG_NO_CHECK_TIME) 

    # Add service certificate to the X.509 store
    store.add_cert(X509.from_cryptography(service_cert)) 

    # Prepare X.509 endorsement certificates
    certs_chain = [X509.from_cryptography(cert) for cert in service_endorsements_certs] 

    # Prepare X.509 node certificate
    node_cert_pem = X509.from_cryptography(node_cert) 

    # Create X.509 store context and verify its certificate
    ctx = X509StoreContext(store, node_cert_pem, certs_chain) 
    ctx.verify_certificate()
  except Exception as e:
    raise VerificationError("Certificate verification failed") from e