import logging
import json
import os
import re
from urllib.parse import quote, unquote, urlparse

import azure.functions as func
import AzureStorageAccount
import msal
import requests

from azure.storage.blob import BlobServiceClient
from azure.core import MatchConditions


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

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ============================================================
# MICROSOFT GRAPH AUTHENTICATION
# ============================================================

def get_graph_token() -> str:

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

    if result is None:
        raise RuntimeError(
            "Microsoft Graph authentication returned no response."
        )

    token = result.get("access_token")

    if not isinstance(token, str) or not token:
        error_message = result.get(
            "error_description",
            result.get("error", "Unknown authentication error")
        )

        raise RuntimeError(
            f"Microsoft Graph authentication failed: {error_message}"
        )

    return token


# ============================================================
# RESOLVE SHAREPOINT DOCUMENT LIBRARY
# ============================================================

def get_sharepoint_drive_id(token: str) -> str:
    """
    Resolve SharePoint site and document library
    using environment variables.

    SHAREPOINT_SITE_URL:
        https://tsacengineering.sharepoint.com/sites/SurveyTeamTest

    SHAREPOINT_LIBRARY_NAME:
        Survey Submissions
    """

    parsed_url = urlparse(
        os.environ["SHAREPOINT_SITE_URL"]
    )

    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or not parsed_url.path.strip("/")
    ):
        raise ValueError("Invalid SHAREPOINT_SITE_URL")

    hostname = parsed_url.hostname
    site_path = parsed_url.path.rstrip("/")
    library_name = os.environ["SHAREPOINT_LIBRARY_NAME"]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # --------------------------------------------------------
    # RESOLVE SITE ID
    # --------------------------------------------------------

    site_url = (
        f"{GRAPH_BASE}/sites/"
        f"{hostname}:{quote(site_path, safe='/')}"
    )

    response = requests.get(
        site_url,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()

    site_id = response.json()["id"]

    logging.info(
        "Resolved SharePoint site: %s",
        site_id
    )

    # --------------------------------------------------------
    # RESOLVE DOCUMENT LIBRARY
    # --------------------------------------------------------

    drives_url = f"{GRAPH_BASE}/sites/{site_id}/drives"

    while drives_url:

        response = requests.get(
            drives_url,
            headers=headers,
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        for drive in data.get("value", []):

            if (
                drive.get("name", "").casefold()
                == library_name.casefold()
            ):

                logging.info(
                    "Resolved SharePoint library: %s",
                    drive["name"]
                )

                return drive["id"]

        drives_url = data.get("@odata.nextLink")

    raise RuntimeError(
        f"SharePoint library '{library_name}' "
        f"not found at {hostname}{site_path}"
    )


# ============================================================
# SHAREPOINT FOLDER NAME VALIDATION
# ============================================================

def safe_folder(value: str) -> str:
    """
    Converts a metadata value into a valid
    SharePoint folder name.
    """

    value = str(value).strip()

    value = re.sub(
        r'["*:<>?/\\|]',
        "_",
        value
    )

    value = value.strip(" .")

    if not value:
        raise ValueError(
            "SharePoint folder name cannot be empty"
        )

    return value


# ============================================================
# SHAREPOINT FOLDER CREATION
# ============================================================

def ensure_sharepoint_folder(
    drive_id: str,
    parent_id: str,
    folder_name: str,
    token: str
) -> str:
    """
    Returns an existing SharePoint folder ID or
    creates the folder if it does not exist.
    """

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    encoded_name = quote(folder_name, safe="")

    if parent_id == "root":

        check_url = (
            f"{GRAPH_BASE}/drives/{drive_id}"
            f"/root:/{encoded_name}"
        )

        create_url = (
            f"{GRAPH_BASE}/drives/{drive_id}/root/children"
        )

    else:

        check_url = (
            f"{GRAPH_BASE}/drives/{drive_id}"
            f"/items/{parent_id}:/{encoded_name}"
        )

        create_url = (
            f"{GRAPH_BASE}/drives/{drive_id}"
            f"/items/{parent_id}/children"
        )

    # --------------------------------------------------------
    # CHECK EXISTING FOLDER
    # --------------------------------------------------------

    response = requests.get(
        check_url,
        headers=headers,
        timeout=30
    )

    if response.status_code == 200:

        item = response.json()

        if "folder" not in item:
            raise RuntimeError(
                f"SharePoint item exists but is not "
                f"a folder: {folder_name}"
            )

        return item["id"]

    if response.status_code != 404:
        response.raise_for_status()

    # --------------------------------------------------------
    # CREATE FOLDER
    # --------------------------------------------------------

    payload = {
        "name": folder_name,
        "folder": {},
        "@microsoft.graph.conflictBehavior": "fail"
    }

    response = requests.post(
        create_url,
        headers=headers,
        json=payload,
        timeout=30
    )

    if response.status_code == 409:

        # Folder may have been created by another invocation
        response = requests.get(
            check_url,
            headers=headers,
            timeout=30
        )

    response.raise_for_status()

    item = response.json()

    if "folder" not in item:
        raise RuntimeError(
            f"SharePoint item is not a folder: {folder_name}"
        )

    logging.info(
        "SharePoint folder ready: %s",
        folder_name
    )

    return item["id"]


# ============================================================
# SHAREPOINT UPLOAD
# ============================================================

def upload_clean_blob_to_sharepoint(
    blob_name: str,
    dmz_credential: str,
    expected_etag: str
) -> dict:
    """
    Upload a Defender-approved blob directly from DMZ
    to SharePoint.

    Folder structure:
        category/
        project_number/
        submitter/
        submission_time/
        blobname

    Metadata provides the four folder names.

    The actual DMZ blob name provides the filename.
    """

    # --------------------------------------------------------
    # RESOLVE SHAREPOINT DESTINATION
    # --------------------------------------------------------

    token = get_graph_token()

    drive_id = get_sharepoint_drive_id(token)

    root_folder = os.environ.get(
        "SHAREPOINT_FOLDER", ""
    ).strip("/")

    # --------------------------------------------------------
    # CONNECT DIRECTLY TO DMZ
    # --------------------------------------------------------

    blob_service_client = BlobServiceClient(
        account_url=DMZ_StorageAccount_URL,
        credential=dmz_credential
    )

    blob_client = blob_service_client.get_blob_client(
        container=InterestedContainer,
        blob=blob_name
    )

    # --------------------------------------------------------
    # READ BLOB METADATA
    # --------------------------------------------------------

    properties = blob_client.get_blob_properties()

    if properties.etag != expected_etag:
        raise RuntimeError(
            f"Blob changed since Defender scan: {blob_name}"
        )

    metadata = properties.metadata or {}

    required_fields = [
        "category",
        "project_number",
        "submitter",
        "submission_time"
    ]

    missing_fields = [
        field
        for field in required_fields
        if not metadata.get(field)
    ]

    if missing_fields:
        raise ValueError(
            f"Missing metadata for {blob_name}: "
            f"{missing_fields}"
        )

    # --------------------------------------------------------
    # BUILD FOLDER PATH FROM METADATA
    # --------------------------------------------------------

    folders = [
        safe_folder(metadata["category"]),
        safe_folder(metadata["project_number"]),
        safe_folder(metadata["submitter"]),
        safe_folder(metadata["submission_time"])
    ]

    if root_folder:

        folders = [
            *[
                safe_folder(folder)
                for folder in root_folder.split("/")
            ],
            *folders
        ]

    # The filename is from the DMZ blob name
    file_name = blob_name.rsplit("/", 1)[-1]

    if not file_name:
        raise ValueError("DMZ blob filename is empty")

    if (
        re.search(r'["*:<>?/\\|]', file_name)
        or file_name.endswith((" ", "."))
        or file_name in (".", "..")
    ):
        raise ValueError(
            f"Invalid SharePoint filename: {file_name}"
        )

    logging.info(
        "SharePoint destination: %s/%s",
        "/".join(folders),
        file_name
    )

    # --------------------------------------------------------
    # CREATE SHAREPOINT FOLDERS
    # --------------------------------------------------------

    parent_id = "root"

    for folder_name in folders:

        parent_id = ensure_sharepoint_folder(
            drive_id=drive_id,
            parent_id=parent_id,
            folder_name=folder_name,
            token=token
        )

    # --------------------------------------------------------
    # DOWNLOAD ORIGINAL DMZ FILE
    # --------------------------------------------------------

    if properties.size > 250 * 1024 * 1024:
        raise ValueError(
            f"File exceeds 250 MB: {blob_name}. "
            "Use a Graph upload session."
        )

    file_data = blob_client.download_blob(
        etag=expected_etag,
        match_condition=MatchConditions.IfNotModified
    ).readall()

    # --------------------------------------------------------
    # UPLOAD FILE TO SHAREPOINT
    # --------------------------------------------------------

    encoded_file_name = quote(file_name, safe="")

    upload_url = (
        f"{GRAPH_BASE}/drives/{drive_id}"
        f"/items/{parent_id}:/{encoded_file_name}:/content"
    )

    headers = {
        "Authorization": f"Bearer {token}",
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
        "Successfully uploaded %s to SharePoint: %s",
        blob_name,
        item.get("webUrl")
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
    Copies a blob using the existing
    AzureStorageAccount class.
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
        "Blob copy operation returned success: %s -> %s",
        blob_name,
        destination_container
    )


# ============================================================
# DELETE DMZ BLOB
# ============================================================

def delete_dmz_blob(
    dmz_client,
    blob_name,
    expected_etag
):
    """
    Deletes the original DMZ blob only if its ETag
    still matches the Defender-scanned blob.
    """

    blob_client = dmz_client.get_blob_client(
        container=InterestedContainer,
        blob=blob_name
    )

    blob_client.delete_blob(
        etag=expected_etag,
        match_condition=MatchConditions.IfNotModified
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

    logging.info(
        "Python EventGrid trigger processed an event"
    )

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
        raise ValueError(
            f"Unexpected Event Grid subject: "
            f"{azeventgrid.subject}"
        )

    StorageAccountName = subject_parts[1]
    ContainerName = subject_parts[3]

    # Actual DMZ blob name
    BlobName = unquote(
        "/".join(subject_parts[5:])
    )

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
        raise ValueError("Event has no blob name")

    if ScanResult not in (
        CleanVerdict,
        MaliciousVerdict
    ):

        logging.warning(
            "Unexpected Defender scan result for %s: %s",
            BlobName,
            ScanResult
        )

        return

    # --------------------------------------------------------
    # VERIFY SCANNED BLOB VERSION
    # --------------------------------------------------------

    expected_etag = event_data.get("blobETag")

    if (
        not isinstance(expected_etag, str)
        or not expected_etag
    ):
        raise RuntimeError(
            f"Defender event has no blobETag for {BlobName}"
        )

    # --------------------------------------------------------
    # CONNECT TO DMZ STORAGE
    # --------------------------------------------------------

    Response_DMZ, DMZ_Blob_ServiceClient = (
        Blob_Class.ConnecttoBlobServiceClient(
            StorageAccount_BlobURL=DMZ_StorageAccount_URL,
            StorageAccount_Credentials=DMZ_Credential,
            Attempts=5
        )
    )

    if not 200 <= Response_DMZ["Code"] < 300: # type: ignore
        raise RuntimeError(
            "Unable to connect to DMZ storage"
        )

    source_blob = DMZ_Blob_ServiceClient.get_blob_client( # type: ignore
        container=InterestedContainer,
        blob=BlobName
    )

    source_properties = source_blob.get_blob_properties()

    if source_properties.etag != expected_etag:
        raise RuntimeError(
            f"DMZ blob changed since Defender scan: {BlobName}"
        )

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
                dmz_credential=DMZ_Credential,
                expected_etag=expected_etag
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
            "Distribution result for %s: "
            "Storage=%s SharePoint=%s",
            BlobName,
            storage_success,
            sharepoint_success
        )

        if storage_success and sharepoint_success:

            delete_dmz_blob(
                dmz_client=DMZ_Blob_ServiceClient,
                blob_name=BlobName,
                expected_etag=expected_etag
            )

            logging.info(
                "Clean file processing completed: %s",
                BlobName
            )

        else:

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

        # Copy to quarantine
        copy_blob(
            blob_class=Blob_Class,
            origin_client=DMZ_Blob_ServiceClient,
            destination_client=DMZ_Blob_ServiceClient,
            origin_credential=DMZ_Credential,
            origin_container=InterestedContainer,
            destination_container=MalwareContainer,
            blob_name=BlobName
        )

        # Delete source after successful quarantine
        delete_dmz_blob(
            dmz_client=DMZ_Blob_ServiceClient,
            blob_name=BlobName,
            expected_etag=expected_etag
        )

        logging.warning(
            "Malicious file quarantined successfully: %s",
            BlobName
        )
