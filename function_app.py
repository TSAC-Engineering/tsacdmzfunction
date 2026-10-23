
import logging
import json
import os
from urllib.parse import quote

import azure.functions as func
import AzureStorageAccount
import msal
import requests

from azure.storage.blob import BlobServiceClient


app = func.FunctionApp()


# ============================================================
# CONFIGURATION
# ============================================================

DMZ_StorageAccount_URL = "https://tsacstoragedmz.blob.core.windows.net/"
Clean_StorageAccount_URL = "https://tsacstorage02.blob.core.windows.net/"

InterestedContainer = "survey123-dmz"
MalwareContainer = "survey123-quarantine"
CleanContainer = "survey123-clean"

AntimalwareScanEventType = "Microsoft.Security.MalwareScanningResult"
MaliciousVerdict = "Malicious"
CleanVerdict = "No threats found"


# ============================================================
# MICROSOFT GRAPH AUTHENTICATION
# ============================================================

def get_graph_token():
    tenant_id = os.environ["SHAREPOINT_TENANT_ID"]
    client_id = os.environ["SHAREPOINT_CLIENT_ID"]
    client_secret = os.environ["SHAREPOINT_CLIENT_SECRET"]

    client = msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret
    )

    result = client.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )

    token = result.get("access_token") # type: ignore

    if not isinstance(token, str) or not token:
        raise RuntimeError(
            "Microsoft Graph authentication failed: "
            + str(result.get("error_description", result.get("error"))) # type: ignore
        )

    return token


# ============================================================
# SHAREPOINT UPLOAD
# ============================================================

def upload_clean_blob_to_sharepoint(blob_name, dmz_credential):
    """
    Downloads a Defender-approved blob directly from the DMZ
    and uploads it to the SharePoint document library.

    Does not depend on the tsacstorage02 copy.
    """

    drive_id = os.environ["SHAREPOINT_DRIVE_ID"]
    folder = os.environ.get("SHAREPOINT_FOLDER", "").strip("/")

    logging.info(
        "Starting SharePoint upload for %s",
        blob_name
    )

    # Connect directly to DMZ storage
    blob_service_client = BlobServiceClient(
        account_url=DMZ_StorageAccount_URL,
        credential=dmz_credential
    )

    blob_client = blob_service_client.get_blob_client(
        container=InterestedContainer,
        blob=blob_name
    )

    # Download the source file
    file_data = blob_client.download_blob().readall()

    if len(file_data) > 250 * 1024 * 1024:
        raise ValueError(
            "File exceeds Microsoft Graph simple upload limit. "
            "Use an upload session."
        )

    # Preserve the relative blob path
    destination_path = (
        f"{folder}/{blob_name}" if folder else blob_name
    )

    encoded_path = quote(destination_path, safe="/")

    upload_url = (
        "https://graph.microsoft.com/v1.0/"
        f"drives/{drive_id}/root:/{encoded_path}:/content"
    )

    headers = {
        "Authorization": f"Bearer {get_graph_token()}",
        "Content-Type": "application/octet-stream"
    }

    response = requests.put(
        upload_url,
        headers=headers,
        data=file_data,
        timeout=120
    )

    response.raise_for_status()

    item = response.json()

    logging.info(
        "SharePoint upload successful. File=%s ItemID=%s",
        blob_name,
        item.get("id")
    )

    return item


# ============================================================
# AZURE BLOB COPY
# ============================================================

def copy_blob(
    blob_class,
    origin_client,
    destination_client,
    origin_credential,
    origin_container,
    destination_container,
    blob_name
):
    """
    Copies a blob using the existing AzureStorageAccount class.
    """

    response, _ = blob_class.TransferDirectoryFile_BlobtoBlob(
        Blob_AccountKey_Origin=origin_credential,
        Blob_ServiceClient_Origin=origin_client,
        Blob_ContainerName_Origin=origin_container,
        Blob_FileDirectoryName_Origin=blob_name,
        Blob_ServiceClient_Copy=destination_client,
        Blob_ContainerName_Copy=destination_container,
        Blob_FileDirectoryName_Copy=blob_name,
        Attempts=5
    )

    if not 200 <= response["Code"] < 300:
        raise RuntimeError(
            f"Blob copy failed for {blob_name} "
            f"to {destination_container}: {response}"
        )

    logging.info(
        "Blob copy request successful: %s -> %s",
        blob_name,
        destination_container
    )


# ============================================================
# AZURE BLOB DELETE
# ============================================================

def delete_dmz_blob(
    blob_class,
    dmz_client,
    blob_name
):
    """
    Deletes the source file after all required
    destinations have succeeded.
    """

    response = blob_class.DeleteBlobs(
        Blob_ServiceClient=dmz_client,
        Blob_ContainerName=InterestedContainer,
        Blob_FileDirectoryName=blob_name,
        Exclusions=[],
        Attempts=5
    )

    if not 200 <= response["Code"] < 300:
        raise RuntimeError(
            f"Unable to delete DMZ blob {blob_name}: {response}"
        )

    logging.info(
        "Successfully deleted %s from DMZ",
        blob_name
    )


# ============================================================
# MICROSOFT DEFENDER EVENT GRID TRIGGER
# ============================================================

@app.event_grid_trigger(arg_name="azeventgrid")
def MDScanner(azeventgrid: func.EventGridEvent):

    logging.info("Python EventGrid trigger processed an event")

    Blob_Class = AzureStorageAccount.StorageAccount()

    DMZ_Credential = os.environ["DMZ_Credential"]
    Clean_Credential = os.environ["Clean_Credential"]

    EventGrid_EventType = azeventgrid.event_type
    EventGrid_ID = azeventgrid.id

    event_data = azeventgrid.get_json()

    logging.info(
        "Event Grid event: %s",
        json.dumps({
            "id": EventGrid_ID,
            "data": event_data,
            "topic": azeventgrid.topic,
            "subject": azeventgrid.subject,
            "event_type": EventGrid_EventType
        })
    )

    # --------------------------------------------------------
    # VALIDATE EVENT TYPE
    # --------------------------------------------------------

    if EventGrid_EventType != AntimalwareScanEventType:
        logging.info(
            "Ignoring event %s. Unexpected event type: %s",
            EventGrid_ID,
            EventGrid_EventType
        )
        return

    # --------------------------------------------------------
    # EXTRACT BLOB INFORMATION
    # --------------------------------------------------------

    subject_parts = azeventgrid.subject.split("/")

    if (
        len(subject_parts) < 6
        or subject_parts[0] != ""
        or subject_parts[2] != "containers"
        or subject_parts[4] != "blobs"
    ):
        logging.error(
            "Unexpected Event Grid subject: %s",
            azeventgrid.subject
        )
        return

    StorageAccountName = subject_parts[1]
    ContainerName = subject_parts[3]
    BlobName = "/".join(subject_parts[5:])

    ScanResult = event_data.get("scanResultType")

    logging.info(
        "StorageAccount=%s Container=%s Blob=%s ScanResult=%s",
        StorageAccountName,
        ContainerName,
        BlobName,
        ScanResult
    )

    # --------------------------------------------------------
    # VALIDATE SOURCE
    # --------------------------------------------------------

    if ContainerName != InterestedContainer:
        logging.info(
            "Ignoring event %s from container %s",
            EventGrid_ID,
            ContainerName
        )
        return

    if StorageAccountName.lower() != "tsacstoragedmz":
        logging.warning(
            "Ignoring event from unexpected storage account: %s",
            StorageAccountName
        )
        return

    if not BlobName:
        logging.error("Event %s has no blob name", EventGrid_ID)
        return

    if ScanResult not in (CleanVerdict, MaliciousVerdict):
        logging.warning(
            "Unexpected Defender scan result for %s: %s",
            BlobName,
            ScanResult
        )
        return

    # --------------------------------------------------------
    # CONNECT TO AZURE STORAGE
    # --------------------------------------------------------

    Response_DMZ, DMZ_Blob_ServiceClient = (
        Blob_Class.ConnecttoBlobServiceClient(
            StorageAccount_BlobURL=DMZ_StorageAccount_URL,
            StorageAccount_Credentials=DMZ_Credential,
            Attempts=5
        )
    )

    if not 200 <= Response_DMZ["Code"] < 300: # type: ignore
        raise RuntimeError("Unable to connect to DMZ storage")

    # ========================================================
    # CLEAN FILE PROCESSING
    # ========================================================

    if ScanResult == CleanVerdict:

        logging.info(
            "Clean file detected: %s. "
            "Distributing to Azure Storage and SharePoint.",
            BlobName
        )

        storage_success = False
        sharepoint_success = False

        # ----------------------------------------------------
        # DESTINATION 1: AZURE STORAGE
        # ----------------------------------------------------

        try:
            Response_Clean, Clean_Blob_ServiceClient = (
                Blob_Class.ConnecttoBlobServiceClient(
                    StorageAccount_BlobURL=Clean_StorageAccount_URL,
                    StorageAccount_Credentials=Clean_Credential,
                    Attempts=5
                )
            )

            if not 200 <= Response_Clean["Code"] < 300: # type: ignore
                raise RuntimeError(
                    "Unable to connect to clean storage account"
                )

            copy_blob(
                blob_class=Blob_Class,
                origin_client=DMZ_Blob_ServiceClient,
                destination_client=Clean_Blob_ServiceClient,
                origin_credential=DMZ_Credential,
                origin_container=InterestedContainer,
                destination_container=CleanContainer,
                blob_name=BlobName
            )

            storage_success = True

        except Exception:
            logging.exception(
                "Azure Storage distribution failed for %s",
                BlobName
            )

        # ----------------------------------------------------
        # DESTINATION 2: SHAREPOINT
        # ----------------------------------------------------

        try:
            upload_clean_blob_to_sharepoint(
                blob_name=BlobName,
                dmz_credential=DMZ_Credential
            )

            sharepoint_success = True

        except Exception:
            logging.exception(
                "SharePoint distribution failed for %s",
                BlobName
            )

        # ----------------------------------------------------
        # VERIFY BOTH DESTINATIONS
        # ----------------------------------------------------

        logging.info(
            "Distribution result for %s: Storage=%s SharePoint=%s",
            BlobName,
            storage_success,
            sharepoint_success
        )

        if storage_success and sharepoint_success:

            logging.info(
                "Both destinations successful for %s",
                BlobName
            )

            delete_dmz_blob(
                blob_class=Blob_Class,
                dmz_client=DMZ_Blob_ServiceClient,
                blob_name=BlobName
            )

            logging.info(
                "Clean file processing completed: %s",
                BlobName
            )

        else:
            # Keep the source so failed destinations can retry
            logging.error(
                "Incomplete distribution for %s. "
                "Original DMZ blob retained.",
                BlobName
            )

            raise RuntimeError(
                f"Distribution incomplete for {BlobName}. "
                f"Storage={storage_success}, "
                f"SharePoint={sharepoint_success}"
            )

    # ========================================================
    # MALICIOUS FILE PROCESSING
    # ========================================================

    elif ScanResult == MaliciousVerdict:

        logging.warning(
            "Malicious file detected: %s",
            BlobName
        )

        # Copy to quarantine in the DMZ account
        copy_blob(
            blob_class=Blob_Class,
            origin_client=DMZ_Blob_ServiceClient,
            destination_client=DMZ_Blob_ServiceClient,
            origin_credential=DMZ_Credential,
            origin_container=InterestedContainer,
            destination_container=MalwareContainer,
            blob_name=BlobName
        )

        # Delete source only after successful quarantine
        delete_dmz_blob(
            blob_class=Blob_Class,
            dmz_client=DMZ_Blob_ServiceClient,
            blob_name=BlobName
        )

        logging.warning(
            "Malicious file quarantined successfully: %s",
            BlobName
        )

        return
    


