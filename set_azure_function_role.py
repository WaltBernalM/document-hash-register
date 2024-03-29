import datetime
import json
import os

from azure.confidentialledger import ConfidentialLedgerClient

def set_azure_function_role(ledger_client: ConfidentialLedgerClient) -> str:
  if os.getenv("ENVIRONMENT") == "development":
    object_id = os.getenv("FUNCTION_OBJECT_PRINCIPAL_ID")
    if object_id is not None:
      assigned_role = "Contributor"
      try:
        user = ledger_client.create_or_update_user(object_id, {"assignedRole": assigned_role})
        return json.dumps(user)
      except Exception as e:
        return f"An error occurred while creating or updating user: {e}."
    else:
      return "FUNCTION_OBJECT_PRINCIPAL_ID is not set. Unable to create or update azure function role."
  return "Production Environment, cannot create or update azure function role."