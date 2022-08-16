using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Configuration;
using SMBLibrary;
using SMBLibrary.Client;
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
            var host = smbSection["host"];
            var sharedFolderName = smbSection["sharedFolderName"];
            var path = smbSection["path"];
            var userName = smbSection["userName"];
            var password = smbSection["password"];

            if (!IPAddress.TryParse(host, out var address))
            {
                var iPHostEntry = Dns.GetHostEntry(host);
                address = iPHostEntry.AddressList.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                if (address == null)
                {
                    Console.WriteLine("Can not get IPV4 address");
                    return;
                }
            }

            #region Connect

            Console.WriteLine("Connect------------- Enter?");
            Console.ReadLine();

            bool isConnected = client.Connect(address, SMBTransportType.DirectTCPTransport);
            if (!isConnected)
            {
                Console.WriteLine("SMB connect failed.");
            }
            Console.WriteLine("SMB connect success.");

            #endregion

            #region Login

            Console.WriteLine("Login------------- Enter?");
            Console.ReadLine();
            var status = client.Login(string.Empty, userName, password);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine($"SMB client Login failed. {status}");
                return;
            }

            #endregion

            #region ListShares

            Console.WriteLine("ListShares------------- Enter?");
            Console.ReadLine();
            var shares = client.ListShares(out status);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine($"SMB client list shares failed. {status}");
                return;
            }

            Console.WriteLine("Shares:");
            foreach (var item in shares)
            {
                Console.WriteLine(item);
            }

            #endregion

            #region TreeConnect

            Console.WriteLine("TreeConnect------------- Enter?");
            Console.ReadLine();

            var fileStore = client.TreeConnect(sharedFolderName, out status);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine($"SMB client TreeConnect failed. {status}");
                return;
            }

            #endregion

            #region CreateFile

            Console.WriteLine("CreateFile------------- Enter?");
            Console.ReadLine();

            var split = string.IsNullOrWhiteSpace(path) ? string.Empty : "\\";
            var fileName = $"{path}{split}{Guid.NewGuid()}.txt";
            var fileContents = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString());
            Console.WriteLine($"FileContent Length:{fileContents.Length}");

            CreateFile(fileStore, fileName, fileContents);

            #endregion

            #region ReadFile

            Console.WriteLine("ReadFile------------- Enter?");
            Console.ReadLine();

            var readFileContents = ReadFile(fileStore, fileName, (int)client.MaxReadSize);
            Debug.Assert(readFileContents != null);
            Debug.Assert(readFileContents.Length == fileContents.Length);
            Console.WriteLine($"Read FileContent Length:{readFileContents.Length}");

            #endregion

            #region Create Directory

            Console.WriteLine("Create Directory------------- Enter?");
            Console.ReadLine();

            for (int i = 0; i < 3; i++)
            {
                var dirPath = Path.Combine(path, Guid.NewGuid().ToString());
                status = CreateDirectory(fileStore, dirPath, null);
                if (status == NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine(dirPath);
                }
            }

            #endregion

            #region Query Directory

            Console.WriteLine("Query Directory------------- Enter?");
            Console.ReadLine();

            var queryDirectoryInfos = QueryDirectory(fileStore, path);
            foreach (var item in queryDirectoryInfos)
            {
                var fileInfo = (item as FileDirectoryInformation);
                Console.WriteLine($"FileName:{fileInfo.FileName} Type:{fileInfo.FileAttributes}");
            }

            #endregion

            #region Delete Directory

            Console.WriteLine("Delete Directory------------- Enter?");
            Console.ReadLine();

            foreach (var item in queryDirectoryInfos)
            {
                var fileInfo = (item as FileDirectoryInformation);
                if (fileInfo.FileAttributes == FileAttributes.Directory && fileInfo.FileName != "." && fileInfo.FileName != "..")
                {
                    Console.WriteLine($"Delete {fileInfo.FileName}");
                    DeleteDirectory(fileStore, Path.Combine(path, fileInfo.FileName));
                }
            }

            #endregion

            #region Delete File

            Console.WriteLine("Delete File------------- Enter?");
            Console.ReadLine();

            DeleteFile(fileStore, fileName);

            #endregion

            #region Disconnect

            Console.WriteLine("Disconnect------------- Enter?");

            fileStore.Disconnect();
            client.Logoff();

            Console.WriteLine("SMB disconnect.");

            #endregion

            Console.ReadLine();
        }

        public static void CreateFile(INTFileStore fileStore, string fullPathWithFileName, byte[] content)
        {
            var status = fileStore.CreateFile(
                   out var fileHandle,
                   out _,
                   fullPathWithFileName,
                   AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE,
                   FileAttributes.Normal,
                   ShareAccess.None,
                   CreateDisposition.FILE_OVERWRITE_IF,
                   CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                   null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("CreateFile failed.");
                return;
            }
            status = fileStore.WriteFile(out _, fileHandle, 0, content);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("WriteFile failed.");
                fileStore.CloseFile(fileHandle);
                return;
            }
            fileStore.CloseFile(fileHandle);
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

        public static List<QueryDirectoryFileInformation> QueryDirectory(INTFileStore fileStore, string relativePath)
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
            if (status != NTStatus.STATUS_SUCCESS)
            {
                throw new Exception("QueryDirectory failed");
            }

            fileStore.QueryDirectory(
                    out List<QueryDirectoryFileInformation> fileList,
                    directoryHandle,
                    "*",
                    FileInformationClass.FileDirectoryInformation);

            fileStore.CloseFile(directoryHandle);

            return fileList;
        }

        public static byte[] ReadFile(INTFileStore fileStore, string fullPathWithFileName, int maxReadSize)
        {
            var status = fileStore.CreateFile(
                   out var fileHandle,
                   out var fileStatus,
                   fullPathWithFileName,
                   AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE,
                   FileAttributes.Normal,
                   ShareAccess.Read,
                   CreateDisposition.FILE_OPEN,
                   CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT,
                   null);

            if (status != NTStatus.STATUS_SUCCESS)
            {
                throw new Exception("Failed to read from file");
            }

            using MemoryStream stream = new MemoryStream();

            long bytesRead = 0;
            while (true)
            {
                status = fileStore.ReadFile(out var data, fileHandle, bytesRead, maxReadSize);
                if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_END_OF_FILE)
                {
                    throw new Exception("Failed to read from file");
                }

                if (status == NTStatus.STATUS_END_OF_FILE || data.Length == 0)
                {
                    break;
                }
                bytesRead += data.Length;
                stream.Write(data, 0, data.Length);
            }

            fileStore.CloseFile(fileHandle);

            return stream.ToArray();
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

            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("DeleteFile failed.");
                return status;
            }

            FileDispositionInformation fileDispositionInformation = new FileDispositionInformation
            {
                DeletePending = true
            };
            status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("DeleteFile failed.");
                return status;
            }
            status = fileStore.CloseFile(fileHandle);

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

            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("DeleteDirectory failed.");
                return status;
            }

            FileDispositionInformation fileDispositionInformation = new FileDispositionInformation
            {
                DeletePending = true
            };
            status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                Console.WriteLine("DeleteDirectory failed.");
                return status;
            }
            status = fileStore.CloseFile(fileHandle);

            return status;
        }
    }
}
