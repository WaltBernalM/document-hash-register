import json

from azure.confidentialledger import ConfidentialLedgerClient

def assign_user_to_ledger(user_id: str, assigned_role: str, ledger_client: ConfidentialLedgerClient) -> str:
  try: 
    user = ledger_client.create_or_update_user(
      user_id, {"assignedRole": assigned_role}
    )
    return json.dumps(user)
  except Exception as e:
    return f"An error occurred while creating or updating user: {e}"

# Assign a previously created User to the ledger client as Contributor
  # username="pcl-app@waltr7hotmail.onmicrosoft.com"
  # password="##########"
  # user_id = "85b06c53-66e0-41ae-9419-944ab12b8a7e"
  # user = ledger_client.create_or_update_user(
  #   user_id, {"assignedRole": "Contributor"}
  # )
  # print('user: ', user)