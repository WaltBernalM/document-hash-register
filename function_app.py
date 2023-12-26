import datetime
import json
import os
import azure.functions as func
import logging

from azure.core.exceptions import HttpResponseError
from azure.confidentialledger import ConfidentialLedgerClient
from azure.confidentialledger.certificate import ConfidentialLedgerCertificateClient
from azure.identity import DefaultAzureCredential
from verify_receipt import verify_receipt
from verify_hash import valid_hash

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="bkch-doc", methods=["POST"])
def bkch_doc(req: func.HttpRequest) -> func.HttpResponse:
  logging.info('Python HTTP trigger function processed a request.')

  try:
    req_body = req.get_json()
    hash_doc = req_body.get('hash')

    # Verify if hash is present in the body request
    if not hash_doc:
      message = { "message": "No document hash provided"}
      return func.HttpResponse(json.dumps(message), status_code=400, mimetype="application/json")
    
    # Verify if the hash provided is in a valid pattern
    regex_pattern = r'^[0-9a-fA-F]+$'
    if not valid_hash(hash_doc, regex_pattern): 
      response = { 
        "message": "Hash not valid",
        "hash": str(hash_doc)
      }
      response_json = json.dumps(response)
      return func.HttpResponse(response_json, status_code=400, mimetype="application/json")
    
    ####################################################################################################################
    # Confidential ledger configuration section
    ####################################################################################################################
    # resource_group = "Test"
    ledger_name = "document-hash"
    collection_id = "subledger:0"
    # subscription_id = "194a93b8-47fc-4913-870e-ff049ecc2307"
    identity_url = "https://identity.confidential-ledger.core.azure.com"
    ledger_url = "https://" + ledger_name + ".confidential-ledger.azure.com"

    # Set of credential to be used for confidential ledger
    credential = DefaultAzureCredential()

    # Creation of Confidential Ledger Certificate
    ledger_tls_cert_file_name = "network_certificate.pem"
    if os.getenv("ENVIRONMENT") != "production":
      identity_client = ConfidentialLedgerCertificateClient(identity_url)
      network_identity = identity_client.get_ledger_identity(ledger_id=ledger_name)
      with open(ledger_tls_cert_file_name, "w") as cert_file:
        cert_file.write(network_identity['ledgerTlsCertificate'])

    # Creation of Confidential Ledger Client
    ledger_client = ConfidentialLedgerClient(
      endpoint=ledger_url,
      credential=credential,
      ledger_certificate_path=ledger_tls_cert_file_name
    )

    # Assign a previously created User to the ledger client as Contributor
    # username="pcl-app@waltr7hotmail.onmicrosoft.com"
    # password="Bemw930628"
    # user_id = "85b06c53-66e0-41ae-9419-944ab12b8a7e"
    # user = ledger_client.create_or_update_user(
    #   user_id, {"assignedRole": "Contributor"}
    # )
    # print('user: ', user)

    # Append of document hash in Confidential Ledger and generation of Transaction Receipt
    data= {
      "documentHash": hash_doc, # "0xd5b797ea27a86e2a4b5fb3d08a20b9d1395e3e27751ff971ef3399335bc2d84b"
      "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    json_string = json.dumps(data, default=lambda x: x.__dict__)
    sample_entry = { "contents": json_string }
    ledger_entry_poller = ledger_client.begin_create_ledger_entry(
      entry=sample_entry, collection_id=collection_id
    )
    ledger_entry_result = ledger_entry_poller.result()
    get_receipt_poller = ledger_client.begin_get_receipt(
      ledger_entry_result["transactionId"]
    )
    receipt = get_receipt_poller.result()
    receipt_json = json.dumps(receipt, default=lambda x: x.__dict__)

    return func.HttpResponse(receipt_json, status_code=201, mimetype="application/json")
  except HttpResponseError as ex:
    response = { "message": f"An error occurred in Confidential Ledger: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
  except ValueError:
      response = {"message": "Invalid JSON body provided"}
      return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
  except Exception as ex:
    response = { "message": f"An unexpected error occurred: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")


@app.route(route="bkch-doc/entry", methods=["GET"])
def bkch_doc_content(req: func.HttpRequest) -> func.HttpResponse:
  try:
    transactionId = req.params.get('transactionId')

    # Verify if transaction id is present in request parameters
    if not transactionId:
      response = { "message": "No transaction ID provided" }
      return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")

    ####################################################################################################################
    # Confidential ledger configuration section
    ####################################################################################################################
    ledger_name = "document-hash"
    identity_url = "https://identity.confidential-ledger.core.azure.com"
    ledger_url = "https://" + ledger_name + ".confidential-ledger.azure.com"

    # Set of credential to be used for confidential ledger
    credential = DefaultAzureCredential()

    # Creation of Confidential Ledger Certificate
    ledger_tls_cert_file_name = "network_certificate.pem"
    if os.getenv("ENVIRONMENT") != "production":
      identity_client = ConfidentialLedgerCertificateClient(identity_url)
      network_identity = identity_client.get_ledger_identity(ledger_id=ledger_name)
      with open(ledger_tls_cert_file_name, "w") as cert_file:
        cert_file.write(network_identity['ledgerTlsCertificate'])

    # Creation of Confidential Ledger Client
    ledger_client = ConfidentialLedgerClient(
      endpoint=ledger_url,
      credential=credential,
      ledger_certificate_path=ledger_tls_cert_file_name
    )

    # Retrieve the entry
    get_entry_poller = ledger_client.begin_get_ledger_entry(transaction_id=transactionId)
    entry = get_entry_poller.result()
    entry_data = entry.get("entry", {})
    contents_json = json.loads(entry_data.get('contents', {}))
    final_entry = {
      "collectionId": entry_data.get("collectionId", ""),
      "contents": contents_json,
      "transactionId": entry_data.get("transactionId")
    }
    response_data = {
      "entry": final_entry,
      "state": entry.get("state", "")
    }
    response_json = json.dumps(response_data, default=lambda x: x.__dict__)
    return func.HttpResponse(response_json, status_code=201, mimetype="application/json")
  except HttpResponseError as ex:
    response = { "message": f"An error occurred in Confidential Ledger: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
  except Exception as ex:
    response = { "message": f"An unexpected error occurred: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")

@app.route(route="bkch-doc/verify-receipt", methods=["POST"])
def bkch_doc_validation(req: func.HttpRequest) -> func.HttpResponse:
  try:
    ####################################################################################################################
    # Confidential ledger configuration section
    ####################################################################################################################
    if os.getenv("ENVIRONMENT") != "production":
      ledger_name = "document-hash"
      identity_url = "https://identity.confidential-ledger.core.azure.com"
      identity_client = ConfidentialLedgerCertificateClient(identity_url)
      network_identity = identity_client.get_ledger_identity(ledger_id=ledger_name)
      ledger_tls_cert_file_name = "network_certificate.pem"
      with open(ledger_tls_cert_file_name, "w") as cert_file:
        cert_file.write(network_identity['ledgerTlsCertificate'])

    # Verification of the certificate against the network_certificate
    with open("network_certificate.pem", "r") as service_certificate_file:
      service_certificate_cert = service_certificate_file.read()
      req_body = req.get_json()

      # Verify if receipt property exists
      receipt = req_body.get("receipt")
      if not receipt:
        response = { "message": "No receipt provided" }
        return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")

      # verification of receipt
      verify_receipt(receipt, service_certificate_cert)
      response = {
        "verificationStatus": "Passed",
        "receiptIsValid": True
      }
      response_json = json.dumps(response)
      return func.HttpResponse(response_json, status_code=200, mimetype="application/json")
  except HttpResponseError as ex:
    response = { "message": f"An error occurred in Confidential Ledger: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
  except ValueError:
    response = {"message": "Invalid JSON body provided"}
    return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
  except Exception as ve:
    failure_message = str(ve)
    response = {
      "verificationStatus": "Failed",
      "receiptIsValid": False,
      "failureMessage": failure_message
    }
    response_json = json.dumps(response)
    return func.HttpResponse(response_json, status_code=400, mimetype="application/json")