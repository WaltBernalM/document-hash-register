from azure.confidentialledger.certificate import ConfidentialLedgerCertificateClient


def write_network_identity_pem(ledger_tls_cert_file_name: str, ledger_name: str, identity_url: str) -> None:
  try: 
    identity_client = ConfidentialLedgerCertificateClient(identity_url)
    network_identity = identity_client.get_ledger_identity(ledger_id=ledger_name)
    with open(ledger_tls_cert_file_name, "w") as cert_file:
      cert_file.write(network_identity['ledgerTlsCertificate'])
  except Exception as e:
    print(f"Error creating network_certificate.pem file: {e}")
