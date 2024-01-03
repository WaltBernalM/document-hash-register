import datetime
import json
import os
import azure.functions as func
import logging

from cffi import VerificationError
from azure.core.exceptions import HttpResponseError
from azure.confidentialledger import ConfidentialLedgerClient
from azure.identity import DefaultAzureCredential
from azure.identity import ManagedIdentityCredential
from set_azure_function_role import set_azure_function_role
from verify_receipt import verify_receipt
from verify_hash import valid_hash
from write_network_identity_pem import write_network_identity_pem

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="bkch-doc", methods=["POST"])
def bkch_doc(req: func.HttpRequest) -> func.HttpResponse:
  logging.info('Python HTTP trigger function (bkch_doc) processed a request.')

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
    ledger_name = str(os.getenv("LEDGER_NAME"))
    collection_id = str(os.getenv("COLLECTION_ID"))
    identity_url = str(os.getenv("IDENTITY_URL"))
    ledger_url = "https://" + ledger_name + ".confidential-ledger.azure.com"

    # Set of credential to be used for confidential ledger
    credential = ManagedIdentityCredential() if os.getenv("ENVIRONMENT") == "production" else DefaultAzureCredential()

    # Creation of Confidential Ledger Certificate
    ledger_tls_cert_file_name = "network_certificate.pem"
    if os.getenv("ENVIRONMENT") != "production":
      write_network_identity_pem(ledger_tls_cert_file_name, ledger_name, identity_url)

    # Creation of Confidential Ledger Client
    ledger_client = ConfidentialLedgerClient(
      endpoint=ledger_url,
      credential=credential,
      ledger_certificate_path=ledger_tls_cert_file_name
    )

    # Assign/update a previously created User or ObjectId to the ledger client as Contributor
    azure_function_user_role = set_azure_function_role(ledger_client)
    logging.info(f"azure function role: {azure_function_user_role}")

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
    error_code = ex.error.code if ex.error else None
    error_message = ex.error.message if ex.error else None
    status_code = ex.status_code
    response = {
      "message": "An error occurred in Confidential Ledger",
      "errorMessage": f"{error_message}",
      "statusCode": f"{status_code}",
      "errorCode": f"{error_code}",
      "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")
  except ValueError:
      response = {"message": "Invalid JSON body provided"}
      return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
  except Exception as ex:
    response = { "message": f"An unexpected error occurred: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")

@app.route(route="bkch-doc/entry", methods=["GET"])
def bkch_doc_content(req: func.HttpRequest) -> func.HttpResponse:
  logging.info('Python HTTP trigger function (bkch_doc_content) processed a request.')

  tokenString = ""

  try:
    transactionId = req.params.get('transactionId')

    # Verify if transaction id is present in request parameters
    if not transactionId:
      response = { "message": "No transaction ID provided" }
      return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")

    ####################################################################################################################
    # Confidential ledger configuration section
    ####################################################################################################################
    ledger_name = str(os.getenv("LEDGER_NAME"))
    identity_url = str(os.getenv("IDENTITY_URL"))
    ledger_url = "https://" + ledger_name + ".confidential-ledger.azure.com"

    # Set of credential to be used for confidential ledger
    credential = ManagedIdentityCredential() if os.getenv("ENVIRONMENT") == "production" else DefaultAzureCredential()

    # Creation of Confidential Ledger Certificate
    ledger_tls_cert_file_name = "network_certificate.pem"
    if os.getenv("ENVIRONMENT") != "production":
      write_network_identity_pem(ledger_tls_cert_file_name, ledger_name, identity_url)

    # Creation of Confidential Ledger Client
    ledger_client = ConfidentialLedgerClient(
      endpoint=ledger_url,
      credential=credential,
      ledger_certificate_path=ledger_tls_cert_file_name
    )

    # Assign/update a previously created User or ObjectId to the ledger client as Contributor
    azure_function_user_role = set_azure_function_role(ledger_client)
    logging.info(f"azure function role: {azure_function_user_role}")

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
    error_code = ex.error.code if ex.error else None
    error_message = ex.error.message if ex.error else None
    status_code = ex.status_code
    response = {
      "message": "An error occurred in Confidential Ledger",
      "errorMessage": f"{error_message}",
      "statusCode": f"{status_code}",
      "errorCode": f"{error_code}",
      "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")
  except Exception as ex:
    response = { "message": f"An unexpected error occurred: {ex}" }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")

@app.route(route="bkch-doc/verify-receipt", methods=["POST"])
def bkch_doc_validation(req: func.HttpRequest) -> func.HttpResponse:
  logging.info('Python HTTP trigger function (bkch_doc_validation) processed a request.')

  try:
    # Verification of the certificate against the network_certificate
    with open("network_certificate.pem", "r") as service_certificate_file:
      service_certificate_cert = service_certificate_file.read()
      req_body = req.get_json()

      # Verify if receipt property exists
      receipt = req_body.get("receipt")
      if not receipt:
        response = { "message": "No receipt provided" }
        return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
      
      # Verify if transactionId property exists
      transaction_id = req_body.get("transactionId")
      if not transaction_id:
        response = { "message": "No transactionId provided" }
        return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")

      ##################################################################################################################
      # Confidential ledger configuration section
      ##################################################################################################################
      ledger_name = str(os.getenv("LEDGER_NAME"))
      identity_url = str(os.getenv("IDENTITY_URL"))
      ledger_url = "https://" + ledger_name + ".confidential-ledger.azure.com"
      ledger_tls_cert_file_name = "network_certificate.pem"

      # Creation of Confidential Ledger Certificate
      if os.getenv("ENVIRONMENT") != "production":
        write_network_identity_pem(ledger_tls_cert_file_name, ledger_name, identity_url)
      
      # Set of credential to be used for confidential ledger
      credential = ManagedIdentityCredential() if os.getenv("ENVIRONMENT") == "production" else DefaultAzureCredential()

      # Creation of Confidential Ledger Client
      ledger_client = ConfidentialLedgerClient(
        endpoint=ledger_url,
        credential=credential,
        ledger_certificate_path=ledger_tls_cert_file_name
      )

      # Assign/update a previously created User or ObjectId to the ledger client as Contributor
      azure_function_user_role = set_azure_function_role(ledger_client)
      logging.info(f"azure function role: {azure_function_user_role}")

      # Retrieve the original transaction receipt
      get_original_full_receipt = ledger_client.begin_get_receipt(transaction_id)
      original_full_receipt = get_original_full_receipt.result()
      original_transaction_id = original_full_receipt.get("transactionId")

      # Verification of the transaction ids
      if transaction_id != original_transaction_id:
        raise VerificationError("Receipt verification failed")

      # verification of receipt
      original_full_receipt_json = json.dumps(original_full_receipt)
      full_receipt_json = json.dumps(req_body)
      if original_full_receipt_json != full_receipt_json:
        raise VerificationError("Receipt verification failed")
      verify_receipt(receipt, service_certificate_cert)
      
      response = {
        "verificationStatus": "Passed",
        "receiptIsValid": True
      }
      response_json = json.dumps(response)
      return func.HttpResponse(response_json, status_code=200, mimetype="application/json")
  except HttpResponseError as ex:
    error_code = ex.error.code if ex.error else None
    error_message = ex.error.message if ex.error else None
    status_code = ex.status_code
    response = {
      "message": "An error occurred in Confidential Ledger",
      "errorMessage": f"{error_message}",
      "statusCode": f"{status_code}",
      "errorCode": f"{error_code}",
      "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")
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