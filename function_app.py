import logging
import azure.functions as func
import AzureStorageAccount
import json
import os


app = func.FunctionApp()

@app.event_grid_trigger(arg_name="azeventgrid")
def MDScanner(azeventgrid: func.EventGridEvent):
    logging.info('Python EventGrid trigger processed an event')
    Blob_Class = AzureStorageAccount.StorageAccount()
    
    DMZ_StorageAccount_URL = "https://tsacstoragedmz.blob.core.windows.net/"
    DMZ_Credential = os.environ["DMZ_Credential"]
    
    Clean_StorageAccount_URL = "https://tsacstorage02.blob.core.windows.net/"
    Clean_Credential = os.environ["Clean_Credential"]

    AntimalwareScanEventType = "Microsoft.Security.MalwareScanningResult"
    MaliciousVerdict = "Malicious"
    CleanVerdict = "No threats found"
    
    MalwareContainer = "survey123-quarantine"
    CleanContainer = "survey123-clean"

    InterestedContainer = "survey123-dmz"
    logging.info(azeventgrid)

    result = json.dumps({
        'id': azeventgrid.id,
        'data': azeventgrid.get_json(),
        'topic': azeventgrid.topic,
        'subject': azeventgrid.subject,
        'event_type': azeventgrid.event_type,
    })
    logging.info(result)

    EventGrid_EventType = azeventgrid.event_type
    EventGrid_ID = azeventgrid.id

    if EventGrid_EventType != AntimalwareScanEventType:
        logging.info("Event Grid " + EventGrid_ID + " is " + EventGrid_EventType + " not " + AntimalwareScanEventType)
        return
    
    separator = "/"

    StorageAccountName = azeventgrid.subject.split(separator)[1]
    ContainerName = azeventgrid.subject.split(separator)[3]
    BlobName = separator.join(azeventgrid.subject.split(separator)[5:])
    EventGrid_Data = azeventgrid.get_json()
    EventGrid_BlobURL = EventGrid_Data['blobUri']
    ScanResult = EventGrid_Data["scanResultType"]

    if ContainerName != InterestedContainer:
        logging.info("Event Grid " + EventGrid_ID + " was ignored because it is from " + ContainerName + " which is not the container of interest (" + InterestedContainer + ").")
        return

    Response_DMZ, DMZ_Blob_ServiceClient = Blob_Class.ConnecttoBlobServiceClient(StorageAccount_BlobURL = DMZ_StorageAccount_URL, StorageAccount_Credentials = DMZ_Credential, Attempts = 5)
    Response_Clean, Clean_Blob_ServiceClient = Blob_Class.ConnecttoBlobServiceClient(StorageAccount_BlobURL = Clean_StorageAccount_URL, StorageAccount_Credentials = Clean_Credential, Attempts = 5)


    if ((Response_DMZ['Code'] >= 200 and Response_DMZ['Code'] < 300) and (Response_Clean['Code'] >= 200 and Response_Clean['Code'] < 300)):
        if ScanResult == MaliciousVerdict:
            CopyContainer = MalwareContainer
            Copy_Blob_ServiceClient = DMZ_Blob_ServiceClient

        elif ScanResult == CleanVerdict:
            CopyContainer = CleanContainer
            Copy_Blob_ServiceClient = Clean_Blob_ServiceClient

        else:
            logging.info("Event Grid " + EventGrid_ID + " scan result was " + ScanResult + " which was not expected.")
            return
        
        Response, Blob_FileDirectoryClient_Copy = Blob_Class.TransferDirectoryFile_BlobtoBlob(Blob_AccountKey_Origin = DMZ_Credential, Blob_ServiceClient_Origin = DMZ_Blob_ServiceClient, Blob_ContainerName_Origin = InterestedContainer, Blob_FileDirectoryName_Origin = BlobName, Blob_ServiceClient_Copy = Copy_Blob_ServiceClient, Blob_ContainerName_Copy = CopyContainer, Blob_FileDirectoryName_Copy = BlobName, Attempts = 5)

        if (Response['Code'] >= 200 and Response['Code'] < 300):  
            logging.info('Successfully copied ' + BlobName)
            Response = Blob_Class.DeleteBlobs(Blob_ServiceClient = DMZ_Blob_ServiceClient, Blob_ContainerName = InterestedContainer, Blob_FileDirectoryName = BlobName, Exclusions = [], Attempts = 5)

            if (Response['Code'] >= 200 and Response['Code'] < 300):
                logging.info('Successfully completed deleted ' + BlobName)
                    
            else:
                logging.error("Unable to delete " + BlobName)
        
        else:
            logging.error("Unable to copy " + BlobName + " to " + CopyContainer)

    else: 
        logging.warning("Unable to connect to " + DMZ_StorageAccount_URL + " or " + Clean_StorageAccount_URL)
        return
    


