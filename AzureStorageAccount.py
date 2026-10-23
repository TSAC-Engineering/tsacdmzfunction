import logging
import os
from azure.storage.blob import BlobServiceClient, ContainerClient, BlobPrefix, StandardBlobTier, generate_blob_sas, BlobSasPermissions
from azure.data.tables import TableServiceClient
from azure.core.credentials import AzureNamedKeyCredential
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class StorageAccount(object):

    def ConnecttoTableServiceClient(self, StorageAccount_TableURL: str, StorageAccount: str, StorageAccount_Credential: str, Attempts: int = 5):

        """
        PURPOSE: Connect to a Table Service Client.
        
        INPUTS: 
            StorageAccount_TableURL: The URL of the table service.
            StorageAccount: The name of the storage account.
            StorageAccount_Credential: The credentials of the storage account.
            Attempts: The number of times the function iterates if it is not successful. 
        
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            Table_ServiceClient: The table service client that was connected to via the function.

        """

        Trials = 0
        ResponseCode = 0
        Table_ServiceClient = ""
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
            try: 
                StorageTable_Credentials = AzureNamedKeyCredential(StorageAccount, StorageAccount_Credential)
                Table_ServiceClient = TableServiceClient(StorageAccount_TableURL, credential = StorageTable_Credentials)
                Message = "OK: Able to connect to " + StorageAccount_TableURL
                Response = {'Code': 200, 'Message': Message}
                logger.info(Response)

            except:
                Message = "Connection Error: Unable to connect to " + StorageAccount_TableURL
                Response = {'Code': 500, 'Message': Message}
                logger.critical(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1 

        return Response, Table_ServiceClient

    def ConnecttoAzureStorageTable(self, Table_ServiceClient: TableServiceClient, StorageAccount_TableName: str, Attempts: int = 5):

        """
        PURPOSE: Connect to a storage account table.
        
        INPUTS: 
            Table_ServiceClient: The table service client of the storage account.
            StorageAccountTableName: The name of the of the table name.
            Attempts: The number of times the function iterates if it is not successful. 
            
        
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            Table_Client: The table client that was connected to via the function.

        """

        Trials = 0
        ResponseCode = 0
        Table_Client = ""
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
            try: 
                Table_Client = Table_ServiceClient.get_table_client(table_name = StorageAccount_TableName)
                Message = "OK: Able to connect to " + StorageAccount_TableName
                Response = {'Code': 200, 'Message': Message}
                logger.info(Response)

            except:
                Message = "Connection Error: Unable to connect to " + StorageAccount_TableName
                Response = {'Code': 500, 'Message': Message}
                logger.critical(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1 

        return Response, Table_Client

    def QueryAzureStorageTable(self, Table_Client, Query_Filter: str, Attempts: int = 5):

        """
        PURPOSE: Obtain results from query.
        
        INPUTS: 
            Table_Client: The table client of the storage account.
            Query_Filter: The string query to obtain filtered results from table.
            Attempts: The number of times the function iterates if it is not successful. 
            
        
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            Results: The results of the query.

        """

        Trials = 0
        ResponseCode = 0
        Results = ""
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
            try: 
                Results = Table_Client.query_entities(Query_Filter)
                Message = "OK: Able to obtain results for the following query " + Query_Filter
                Response = {'Code': 200, 'Message': Message}
                logger.info(Response)

            except:
                Message = "Not Implemented: Unbble to obtain results for the following query " + Query_Filter
                Response = {'Code': 501, 'Message': Message}
                logger.critical(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1 

        return Response, Results
    
    
    def ConnecttoBlobServiceClient(self, StorageAccount_BlobURL: str, StorageAccount_Credentials: str, Attempts: int = 5):

        """
        PURPOSE: Connect to Blob Service Client in a storage account.
        
        INPUTS: 
            StorageAccount_BlobURL: The URL of the blob service.
            StorageAccount_Credential: The credentials of the storage account.
            Attempts: The number of times the function iterates if it is not successful. 
            
        
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            Blob_ServiceClient: The blob service client connected to during the function.

        """

        Trials = 0
        ResponseCode = 0
        Blob_ServiceClient = ""
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
            try: 
                Blob_ServiceClient = BlobServiceClient(StorageAccount_BlobURL, credential = StorageAccount_Credentials)
                Message = "OK: Able to connect to " + Blob_ServiceClient.url
                Response = {'Code': 200, 'Message': Message}
                logger.info(Response)

            except:
                Message = "Connection Error: Unable to connect to " + Blob_ServiceClient.url
                Response = {'Code': 500, 'Message': Message}
                logger.critical(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1 

        return Response, Blob_ServiceClient

    def ListBlobs_Flat(self, Blob_ServiceClient: BlobServiceClient, Blob_ContainerName: str, Attempts: int = 5):

        """
        PURPOSE: List all the directories and files within a specific blob container within a Azure Blob Storage Account.
        
        INPUTS: 
            Blob_ServiceClient: The BlobServiceClient of the Azure Blob Storage Account.
            Blob_ContainerName: The name of the container within the BlobServiceClient.
            Attempts: The number of times the function iterates if it is not successful. 
        
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            Blob_DirectoriesFilesList: List of directories and files within the blob, including their name and properties.

        """

        Trials = 0
        ResponseCode = 0
        Blob_DirectoriesFiles_List = []
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):

            try: 
                Blob_ContainerClient = Blob_ServiceClient.get_container_client(container=Blob_ContainerName)
                Blob_DirectoriesFiles_List = list(Blob_ContainerClient.list_blobs())
                Message = "OK: Able to access a list of files/directory from " + Blob_ContainerName + " in " + Blob_ServiceClient.url
                Response = {'Code': 200, 'Message': Message}
                logger.info(Response)
        
            except:
                Message = "Connection Error: Unable to connect to" + Blob_ContainerName + " in " + Blob_ServiceClient.url
                Response = {'Code': 500, 'Message': Message}
                logger.critical(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1 
        
        return Response, Blob_DirectoriesFiles_List

    
    def TransferDirectoryFile_BlobtoComputer(self, Blob_ServiceClient: BlobServiceClient, Blob_ContainerName: str, Blob_FileDirectoryName: str,  Computer_OSType: str, Computer_SaveLocation: str, Attempts: int = 5):

        """
        PURPOSE: Add Directory / File from Azure Blob Storage Account to Computer Location.
        
        INPUTS: 
            Blob_ServiceClient: The BlobServiceClient of the Azure Blob Storage Account.
            Blob_ContainerName: The name of the container within the BlobServiceClient.
            Blob_FileDirectoryName: The name of the file or directory to move within the blob container.
            Computer_OSType: Indicate if the computer is a Windows or Darwin (e.g., MacOS) operating system. 
            Computer_SaveLocation: The high-level path on the computer to save the file or directory.
            Attempts: The number of times the function iterates if it is not successful. 
        
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            FilePath: Filepath of the saved file on the computer. Accounts for the necessary changes to prevent overriding an exisiting file.

        """

        Trials = 0
        ResponseCode = 0
        FilePath = ""
        Response = None

        if Computer_OSType == "Windows":
            FilePath_Delimiter = "\\"
        
        elif Computer_OSType == "Darwin": 
            FilePath_Delimiter = "/"
        
        else:
            Message = "Not Implemented: Computer OS Type muse be Windows or MacOS"
            Response = {'Code': 501, 'Message': Message}
            logger.warning(Response)
            return Response, FilePath
        
        FilePath = Computer_SaveLocation + FilePath_Delimiter + Blob_FileDirectoryName
        FilePath_Extension = os.path.splitext(FilePath)[1]

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):

            if FilePath_Extension == "":
                try:
                    if not os.path.exists(FilePath):
                        os.mkdir(FilePath)
                        Message = "Created: Folder " + FilePath + " was successfully created!"
                        Response = {'Code': 201, 'Message': Message}
                        logger.info(Response)
                
                    else: 
                        Message = "Accepted: Folder " + FilePath + " already exists"
                        Response = {'Code': 202, 'Message': Message}
                        logger.info(Response)
            
                except:
                    FilePath = ""
                    Message = "Not Implemented: Unable to create " + FilePath + " Folder"
                    Response = {'Code': 501, 'Message': Message}
                    logger.warning(Response)

            else: 
                try: 
                    Blob_FileDirectoryClient = Blob_ServiceClient.get_blob_client(container = Blob_ContainerName, blob=Blob_FileDirectoryName)
                    logger.info("Successfully connected to " + Blob_FileDirectoryName + " in " + Blob_ContainerName)
            
                except: 
                    FilePath = ""
                    Message = "Connection Error: Unable to connect to " + Blob_FileDirectoryName + " in " + Blob_ContainerName
                    Response = {'Code': 500, 'Message': Message}
                    logger.warning(Response)
            
            
                try:
                    Blob_FileDirectoryClient_Download = Blob_FileDirectoryClient.download_blob() 
                    logger.info("Successfully downloaded " + Blob_FileDirectoryName + " in " + Blob_ContainerName)

                    
            
                except:
                    FilePath = ""
                    Message = "Download Error: Unable to connect download " + Blob_FileDirectoryName + " in " + Blob_ContainerName
                    Response = {'Code': 501, 'Message': Message}
                    logger.warning(Response)
            
                if os.path.exists(FilePath):
                    i = 0
                    FilePath_Start = os.path.splitext(FilePath)[0]
                    while(os.path.exists(FilePath) == True):
                        i = i + 1
                        FilePath = FilePath_Start + "(" + str(i) + ")" + FilePath_Extension
                
                try:
                    with open(file=FilePath, mode = "wb") as File:
                        File.write(Blob_FileDirectoryClient_Download.readall())
                    Message = "Created: File " + FilePath + " was successfully created!"
                    Response = {'Code': 201, 'Message': Message}
                    logger.info(Response)
            
                except:
                    FilePath = ""
                    Message = "Not Implemented: Unable to create " + FilePath + " File"
                    Response = {'Code': 501, 'Message': Message}
                    logger.warning(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1 

        return Response, FilePath
        

    def TransferDirectoryFile_BlobtoBlob(self, Blob_AccountKey_Origin: str, Blob_ServiceClient_Origin: BlobServiceClient, Blob_ContainerName_Origin: str, Blob_FileDirectoryName_Origin: str, Blob_ServiceClient_Copy: BlobServiceClient, Blob_ContainerName_Copy: str, Blob_FileDirectoryName_Copy: str, Attempts:int = 5):
        
        """
        PURPOSE: Transfer Blob File from one Azure Blob Storage Container to another Azure Blob Storage Container.
        
        INPUTS: 
            Blob_ServiceClient_Origin: The BlobServiceClient of the starting Azure Blob Storage Account.
            Blob_ContainerName_Origin: The name of the container within the starting BlobServiceClient.
            Blob_FileDirectory_Origin: The name of the file or directory to move within the origin blob container.
            Blob_ServiceClient_Copy: The BlobServiceClient of the ending Azure Blob Storage Account.
            Blob_ContainerName_Copy: The name of the container within the ending BlobServiceClient.
            Blob_FileDirectory_Copy: The name of the file or directory to move within the origin blob container.
            Attempts: The number of times the function iterates if it is not successful. 
            
        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
            Blob_FileDirectoryClient_Copy: The blob service client.

        """
        Trials = 0
        ResponseCode = 0
        FilePath_Extension = os.path.splitext(Blob_FileDirectoryName_Origin)[1]
        Blob_FileDirectoryClient_Copy = ""
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
        
            if FilePath_Extension != "":
                try:
                    Blob_FileDirectoryClient_Origin = Blob_ServiceClient_Origin.get_blob_client(container = Blob_ContainerName_Origin, blob=Blob_FileDirectoryName_Origin)
                    Blob_FileDirectoryURL_Origin = Blob_FileDirectoryClient_Origin.url
                    logger.info("Successfully connected to " + Blob_FileDirectoryName_Origin + " in "  + Blob_ContainerName_Origin)
            
                except:
                    Message = "Connection Error: Unable to connect to " + Blob_FileDirectoryName_Origin +  " in " + Blob_ContainerName_Origin
                    Response = {'Code': 500, 'Message': Message}
                    logger.warning(Response)

                try: 
                    Blob_FileDirectoryClient_Copy = Blob_ServiceClient_Copy.get_blob_client(container = Blob_ContainerName_Copy, blob=Blob_FileDirectoryName_Copy)

                    sas_permissions = BlobSasPermissions(read=True, write=True, list=True)
                    expiry_time = datetime.utcnow() + timedelta(minutes=15)

                    sas_token = generate_blob_sas(
                    account_name=Blob_ServiceClient_Origin.account_name,
                    container_name=Blob_ContainerName_Origin,
                    blob_name=Blob_FileDirectoryName_Origin,
                    account_key=Blob_AccountKey_Origin,
                    permission=sas_permissions,
                    expiry=expiry_time
                    )

                    Blob_Origin_url_with_sas = f"https://{Blob_ServiceClient_Origin.account_name}.blob.core.windows.net/{Blob_ContainerName_Origin}/{Blob_FileDirectoryName_Origin}?{sas_token}"
                    print(Blob_Origin_url_with_sas)

                    Copy_Response = Blob_FileDirectoryClient_Copy.start_copy_from_url(Blob_Origin_url_with_sas, requires_sync = True)

                    if Copy_Response["copy_status"] == "success":
                        Message = "Created: Successfully moved " + Blob_FileDirectoryName_Origin + " to " + Blob_ContainerName_Copy + " as " + Blob_FileDirectoryName_Copy + "!"
                        Response = {'Code': 201, 'Message': Message}
                        logger.info(Response)

                    else:
                        Message = "Not Implemented: Unable to moved " + Blob_FileDirectoryName_Origin + " to " + Blob_ContainerName_Copy + " as " + Blob_FileDirectoryName_Copy
                        Response = {'Code': 501, 'Message': Message}
                        logger.warning(Response)
            
                except: 
                    Message = "Not Implemented: Unable to moved " + Blob_FileDirectoryName_Origin + " to " + Blob_ContainerName_Copy + " as " + Blob_FileDirectoryName_Copy
                    Response = {'Code': 501, 'Message': Message}
                    logger.warning(Response)

            else:
                Message = "OK: " + Blob_FileDirectoryName_Origin + " is a Directory not a blob file to transfer"
                Response = {'Code': 200, 'Message': Message}
                logger.info(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1
        
        return Response, Blob_FileDirectoryClient_Copy

    def Change_BlobAccessTier(self, BlobClient, BlobTier: str, Attempts: int = 5):


        """
        PURPOSE: Change the blob access tier.
        
        INPUTS: 
            BlobClient: The BlobClient of the Azure file that should be changed.
            BlobTier: The level to change the BlobClient to. It needs to be Hot, Cool, Cold, or Archieve.
            Attempts: The number of times the function iterates if it is not successful. 

        OUTPUT:
            Response: The response of the function. All 200 response codes indicate the function was successful.
        """
        Trials = 0
        ResponseCode = 0
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
            try: 
                if BlobTier == "Hot":
                    Message = "OK: Successfully change the blob tier to " + BlobTier + "."
                    Response = {'Code': 200, 'Message': Message}
                    BlobClient.set_standard_blob_tier(StandardBlobTier.HOT)
        
                elif BlobTier == "Cool":
                    Message = "OK: Successfully change the blob tier to " + BlobTier + "."
                    Response = {'Code': 200, 'Message': Message}
                    BlobClient.set_standard_blob_tier(StandardBlobTier.COOL)
        
                elif BlobTier == "Cold":
                    Message = "OK: Successfully change the blob tier to " + BlobTier + "."
                    Response = {'Code': 200, 'Message': Message}
                    BlobClient.set_standard_blob_tier(StandardBlobTier.COLD)

                elif BlobTier == "Archieve":
                    BlobClient.set_standard_blob_tier(StandardBlobTier.ARCHIEVE)

                else: 
                    Message = "Not Implemented: " + BlobTier + " is not a valid tier it needs to be Hot, Cool, Cold, or Archieve"
                    Response = {'Code': 501, 'Message': Message}
            
                logger.info(Response)

            except: 
                Message = "Not Implemented: Unable to successfully change the blob tier to " + BlobTier + "."
                Response = {'Code': 501, 'Message': Message}
                logger.Error(Response)

            ResponseCode = Response['Code']
            Trials = Trials + 1

        return Response

    def DeleteBlobs(self, Blob_ServiceClient: BlobServiceClient, Blob_ContainerName: str, Blob_FileDirectoryName: str, Exclusions: list= [], Attempts: int = 5):
        """
        PURPOSE: Delete items in Azure Blob Storage Container.
        
        INPUTS: 
            Blob_ServiceClient: The BlobServiceClient of the Azure Blob Storage Account.
            Blob_ContainerName: The name of the container within the BlobServiceClient.
            Blob_FileDirectoryName: The name of the file or directory to delete within the blob container.
            Exclusions: List of files / directories to exclude from deleting within Azure Blob Storage Account. Default value is an empty list.
            Attempts: The number of times the function iterates if it is not successful. 

        OUTPUTS: 
            Response: The response of the function. All 200 response codes indicate the function was successful.
        """

        Trials = 0
        ResponseCode = 0
        Response = None

        while((ResponseCode < 200 or ResponseCode >=300) and Trials < Attempts):
            if Blob_FileDirectoryName not in Exclusions:
                try: 
                    Blob_FileDirectoryClient = Blob_ServiceClient.get_blob_client(container = Blob_ContainerName, blob=Blob_FileDirectoryName)
                    Blob_FileDirectoryClient.delete_blob()
                    Message = "OK: Successfully deleted " + Blob_FileDirectoryName + " from " + Blob_ContainerName + "!"
                    Response = {'Code': 200, 'Message': Message}
                    logger.info(Response)
            
                except:
                    Message = "Not Implemented: Unable to delete " + Blob_FileDirectoryName + " from " + Blob_ContainerName + "."
                    Response = {'Code': 501, 'Message': Message}
                    logger.warning(Response)
                    return Response
        
            else:
                Message = "OK: Not deleted since" + Blob_FileDirectoryName + " is in exclusion list!"
                Response = {'Code': 200, 'Message': Message}

            ResponseCode = Response['Code']
            Trials = Trials + 1
            
        return Response

