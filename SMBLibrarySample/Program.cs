using Microsoft.Extensions.Configuration;
using SMBLibrary;
using SMBLibrary.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Unicode;
using FileAttributes = SMBLibrary.FileAttributes;

namespace SmbHelper
{
    class Program
    {
        static void Main(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                 .SetBasePath(Directory.GetCurrentDirectory())
                 .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                 .AddUserSecrets(typeof(Program).Assembly, true)
                 .Build();

            Console.WriteLine("Smb start!");
            var client = new SMB2Client(); // SMB2Client can be used as well

            var smbSection = configuration.GetSection("SMB");
            var host = smbSection["host"]; //10.0.10.2
            var sharedFolderName = smbSection["sharedFolderName"];//Users
            var path = smbSection["path"];//Path administrator\shared
            var userName = smbSection["userName"];
            var password = smbSection["password"];

            if (!IPAddress.TryParse(host, out var address))
            {
                var iPHostEntry = Dns.GetHostEntry(host);
                if (iPHostEntry.AddressList.Length == 0)
                {
                    return;
                }
                address = iPHostEntry.AddressList[0];
            }

            //\\10.0.10.2\Users\Administrator\shared
            bool isConnected = client.Connect(address, SMBTransportType.DirectTCPTransport);
            if (!isConnected)
            {
                Console.WriteLine("SMB connect failed.");
            }

            var status1 = client.Login(string.Empty, userName, password);
            if (status1 == NTStatus.STATUS_SUCCESS)
            {
                List<string> shares = client.ListShares(out status1);

                Console.WriteLine("SMB connect success.");
                Console.WriteLine("Shares:");
                foreach (var item in shares)
                {
                    Console.WriteLine(item);
                }
            }
            Console.WriteLine("-------------");

            var fileStore = client.TreeConnect(sharedFolderName, out var status);

            Console.WriteLine("Create File");
            var fileName = path + new Guid("9068e397-de24-4ede-a340-7255af5cd53c") + ".txt";

            var fileHandle = CreateFile(fileStore, fileName, Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));
            Console.WriteLine("-------------");

            Console.WriteLine("Create Directory");
            for (int i = 0; i < 3; i++)
            {
                var dirPath = Path.Combine(path, Guid.NewGuid().ToString());
                status = CreateDirectory(fileStore, dirPath, null);
                if (status == NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine(dirPath);
                }
            }
            Console.WriteLine("-------------");

            Console.WriteLine("Query Directory");
            var queryDirectoryInfos = QueryDirectory(fileStore, path);
            foreach (var item in queryDirectoryInfos)
            {
                Console.WriteLine((item as SMBLibrary.FileDirectoryInformation)?.FileName);
            }
            Console.WriteLine("-------------");


            Console.WriteLine("Delete Directory");
            foreach (var item in queryDirectoryInfos)
            {
                var fileInfo = (item as SMBLibrary.FileDirectoryInformation);
                if (fileInfo.FileAttributes == FileAttributes.Directory)
                {
                    DeleteDirectory(fileStore, Path.Combine(path, fileInfo.FileName));
                }
            }
            Console.WriteLine("-------------");


            Console.WriteLine("Delete File");
            DeleteFile(fileStore, fileHandle);
            Console.WriteLine("-------------");

            fileStore.Disconnect();
            client.Logoff();

            Console.WriteLine("SMB disconnect.");
        }

        public static object CreateFile(INTFileStore fileStore, string fullPathWithFileName, byte[] content)
        {
            var status = fileStore.CreateFile(
                   out var fileHandle,
                   out _,
                   fullPathWithFileName,
                   AccessMask.GENERIC_WRITE | AccessMask.DELETE | AccessMask.SYNCHRONIZE,
                   FileAttributes.Normal,
                   ShareAccess.None,
                   CreateDisposition.FILE_OVERWRITE_IF,
                   CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                   null);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                status = fileStore.WriteFile(out _, fileHandle, 0, content);
            }
            return fileHandle;

        }

        public static NTStatus CreateDirectory(INTFileStore fileStore, string relativePath, SecurityContext securityContext)
        {
            NTStatus createStatus = fileStore.CreateFile(
                out var directoryHandle,
                out var fileStatus,
                relativePath,
                (AccessMask)DirectoryAccessMask.FILE_ADD_SUBDIRECTORY,
                0,
                ShareAccess.Read | ShareAccess.Write,
                CreateDisposition.FILE_CREATE,
                CreateOptions.FILE_DIRECTORY_FILE,
                securityContext);
            if (createStatus != NTStatus.STATUS_SUCCESS)
            {
                return createStatus;
            }
            fileStore.CloseFile(directoryHandle);
            return createStatus;
        }

        public static List<QueryDirectoryFileInformation> QueryDirectory(INTFileStore fileStore, string relativePath = "", bool onlyDir = false)
        {
            var status = fileStore.CreateFile(
                out var directoryHandle,
                out var fileStatus,
                relativePath,
                AccessMask.GENERIC_READ,
                FileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
                null);
            if (status == NTStatus.STATUS_SUCCESS)
            {
                fileStore.QueryDirectory(
                    out List<QueryDirectoryFileInformation> fileList,
                    directoryHandle,
                    "*",
                    FileInformationClass.FileDirectoryInformation);

                fileStore.CloseFile(directoryHandle);

                return fileList;
            }

            throw new Exception("QueryDirectory failed");
        }

        public static NTStatus DeleteFile(INTFileStore fileStore, string filePath)
        {
            var status = fileStore.CreateFile(
                out object fileHandle,
                out FileStatus fileStatus,
                filePath,
                AccessMask.GENERIC_WRITE | AccessMask.DELETE | AccessMask.SYNCHRONIZE,
                FileAttributes.Normal,
                ShareAccess.None,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                null);

            if (status == NTStatus.STATUS_SUCCESS)
            {
                FileDispositionInformation fileDispositionInformation = new FileDispositionInformation
                {
                    DeletePending = true
                };
                status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
                bool deleteSucceeded = (status == NTStatus.STATUS_SUCCESS);
                status = fileStore.CloseFile(fileHandle);
            }

            return status;
        }

        public static NTStatus DeleteFile(INTFileStore fileStore, object fileHandle)
        {
            FileDispositionInformation fileDispositionInformation = new();
            fileDispositionInformation.DeletePending = true;
            var status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
            bool deleteSucceeded = (status == NTStatus.STATUS_SUCCESS);
            status = fileStore.CloseFile(fileHandle);

            return status;
        }

        public static NTStatus DeleteDirectory(INTFileStore fileStore, string filePath)
        {
            var status = fileStore.CreateFile(
                out object fileHandle,
                out FileStatus fileStatus,
                filePath,
                AccessMask.GENERIC_WRITE | AccessMask.DELETE | AccessMask.SYNCHRONIZE, FileAttributes.Normal,
                ShareAccess.None,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_DIRECTORY_FILE,
                null);

            if (status == NTStatus.STATUS_SUCCESS)
            {
                FileDispositionInformation fileDispositionInformation = new FileDispositionInformation
                {
                    DeletePending = true
                };
                status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
                bool deleteSucceeded = (status == NTStatus.STATUS_SUCCESS);
                status = fileStore.CloseFile(fileHandle);
            }

            return status;
        }
    }
}
