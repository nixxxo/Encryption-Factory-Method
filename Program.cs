using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace JPL_Internship
{   
    // ! GLOBAL
    public class EncryptedJson
    {
        public string jType { get; set; }
        public string jHash { get; set; }
        public string jData { get; set; }

        
        public string FileToString (string path)
        {   
            StreamReader r = new StreamReader(path);
            string jsonString = r.ReadToEnd();

            return jsonString;
        }
        public EncryptedJson LoadJson(string path)
        {
            string file = FileToString(path);
            EncryptedJson json = Newtonsoft.Json.JsonConvert.DeserializeObject<EncryptedJson>(file);
            return json;
        }

        public void EncodedJson(string type, string hash, string data, string encrFileName)
        {
            EncryptedJson json = new EncryptedJson();
            json.jType = type;
            json.jHash = hash;
            json.jData = data;
            string jsonReady = JsonSerializer.Serialize(json);
            File.WriteAllText(@$"{encrFileName}", jsonReady);
        }

    }

    // * ENCRYPTION
    abstract class Encr{
        public abstract string Type { get; set;}
        public abstract string Data { get; set; }
        public abstract string EncrFileName { get; set; }

    }

    abstract class EncrFactory{
        public abstract Encr GetEncr();
    }

    class Encryption : EncrFactory
    {
        private string _type;
        private string _data;  
        private string _encrFileName;  
  
        public Encryption(string type, string data, string encrFileName)  
        {  
            _type = type;
            _data = data;  
            _encrFileName = encrFileName;  
        }  
  
        public override Encr GetEncr()  
        {  
            return new EncryptionFactory(_type, _data, _encrFileName);  
        }  

    }

    class EncryptionFactory : Encr {

        private string _type;
        private string _data;
        private string _encrFileName;

        public EncryptionFactory(string type, string data, string encrFileName)
        {
            _type = type;
            _encrFileName = encrFileName;
            EncryptedJson json = new EncryptedJson();

            if (type == "1") {
                var asymKeys = GenerateAssymetricKeys();
                string publicKey = asymKeys.Item1;
                string privateKey = asymKeys.Item2;
                Console.WriteLine("Public key: ");
                Console.WriteLine(publicKey);
                Console.WriteLine("Private key: ");
                Console.WriteLine(privateKey);

                var dataToEncrypt = AEncrypt(publicKey, data);

                _data = dataToEncrypt;

                json.EncodedJson(_type, publicKey, dataToEncrypt, _encrFileName);
            }
            else {

                var key = ConvertCryptoKeyToStr(GenerateCryptoKey());  

                Console.WriteLine();
                Console.WriteLine("Symmetric Key: ");
                Console.WriteLine(key);
                Console.WriteLine();

                var dataToEncrypt = SEncrypt(key, data);  
                var hash = GenerateHash(data);
                _data = dataToEncrypt;

                json.EncodedJson(_type, hash, dataToEncrypt, _encrFileName);

            }

        }

        public override string Type
        {
            get{return _type; }
            set {_type = value;} 
        }

        public override string Data 
        { 
            get {return _data; }
            set {_data = value;} 
        }

        public override string EncrFileName
        {
            get {return _encrFileName; }
            set {_encrFileName = value;} 
        }

        // * ASYMMETRIC
        public string AEncrypt(string publicKey, string data)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey); 
                var byteData = Encoding.UTF8.GetBytes(data);
                var encryptData = rsa.Encrypt(byteData, false);
                return Convert.ToBase64String(encryptData);
            }
        }

        public (string, string) GenerateAssymetricKeys(){
            
            var rsa = new RSACryptoServiceProvider(2048);  
            string publicKey = rsa.ToXmlString(false);// sending this to a friend
            string privateKey = rsa.ToXmlString(true); // private key

            return (publicKey, privateKey);   

        }

        // * SYMMETRIC
        public Aes GenerateCryptoKey(){
            Aes aes = Aes.Create();  
            aes.GenerateIV();  
            aes.GenerateKey();
            return aes;
        }
        public string ConvertCryptoKeyToStr(Aes aes){
            string sKey = Convert.ToBase64String(aes.IV);
            return sKey;
        }
        public byte[] ConvertCryptoKeyToByte(string key){
            byte[] byteKey= Convert.FromBase64String(key);
            return byteKey;
        }

        public string GenerateHash(string data)
        {
            StringBuilder stringBdr = new StringBuilder(); // repeated modifications to a string

            byte[] textBytes = Encoding.ASCII.GetBytes(data); // converting string to into a bytes array

            using (SHA1 encr = SHA1.Create())
            {
                byte[] generateHash = encr.ComputeHash(textBytes);

                for (int i = 0; i<generateHash.Length; i++)
                {
                    stringBdr.Append(generateHash[i].ToString("x2")); // hexadecimal string conversion
                }

                return stringBdr.ToString();
            }

        }
        public string SEncrypt(string key, string data)  
        {  
            byte[] iv = new byte[16];  
            byte[] array;  
  
            using (Aes aes = Aes.Create())  
            {  
                aes.Key = Encoding.UTF8.GetBytes(key);  
                aes.IV = iv;  
  
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);  
  
                using (MemoryStream memoryStream = new MemoryStream())  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))  
                    {  
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))  
                        {  
                            streamWriter.Write(data);  
                        }  
  
                        array = memoryStream.ToArray();  
                    }  
                }  
            }  
  
            return Convert.ToBase64String(array);  
        }  

    }



    // * DECRYPTION
    abstract class Decr{
        public abstract string EncrFileName { get; set; }

    }

    abstract class DecrFactory{
        public abstract Decr GetDecr();
    }

    class Decryption: DecrFactory
    {
        private string _encrFileName;  
  
        public Decryption(string encrFileName)  
        {  
            _encrFileName = encrFileName;  
        }  
  
        public override Decr GetDecr()  
        {  
            return new DecryptionFactory(_encrFileName);  
        } 

    }

    class DecryptionFactory : Decr{

        private string _encrFileName;

        public DecryptionFactory(string encrFileName)
        {
            _encrFileName = encrFileName;

            EncryptedJson json = new EncryptedJson();
            EncryptedJson encrInfo = json.LoadJson(_encrFileName);



            if (encrInfo.jType == "1")
            {
                // * DECRYPTING - Assymmetric

                Console.Write("Private key: ");
                string _key = Console.ReadLine();

                string publicKey_decr = encrInfo.jHash;
                string e_decr = encrInfo.jData;

                var decrMessage = ADecrypt(e_decr, _key);
                Console.WriteLine();
                Console.WriteLine("Decrypted message: " + decrMessage);

            }
            else
            {
                // * DECRYPTING - Symmetric

                Console.Write("Symmetric key: ");
                string _key = Console.ReadLine();


                string h_decr = encrInfo.jHash;
                string e_decr = encrInfo.jData;
                

                string decrypted_e = SDecrypt(_key, e_decr);
                string h1 = GenerateHash(decrypted_e);

                if (string.Equals(h_decr, h1))
                {
                    Console.WriteLine();
                    Console.WriteLine("Decrypted Message: " + decrypted_e);
                }
            }



        }

        public override string EncrFileName
        {
            get {return _encrFileName; }
            set {_encrFileName = value;} 
        }

        // * ASYMMETRIC
        public string ADecrypt(string cipherText, string privateKey)
        {

            using (var rsa = new RSACryptoServiceProvider())
            {
                var cipherByteData = Convert.FromBase64String(cipherText);
                rsa.FromXmlString(privateKey); 

                var encryptData = rsa.Decrypt(cipherByteData, false);
                return Encoding.UTF8.GetString(encryptData);
            }
        }

        // * SYMMETRIC
        public string GenerateHash(string data)
        {
            StringBuilder stringBdr = new StringBuilder(); // repeated modifications to a string

            byte[] textBytes = Encoding.ASCII.GetBytes(data); // converting string to into a bytes array

            using (SHA1 encr = SHA1.Create())
            {
                byte[] generateHash = encr.ComputeHash(textBytes);

                for (int i = 0; i<generateHash.Length; i++)
                {
                    stringBdr.Append(generateHash[i].ToString("x2")); // hexadecimal string conversion
                }

                return stringBdr.ToString();
            }

        }
  
        public string SDecrypt(string key, string cipherText)  
        {  
            byte[] iv = new byte[16];  
            byte[] buffer = Convert.FromBase64String(cipherText);  
  
            using (Aes aes = Aes.Create())  
            {  
                aes.Key = Encoding.UTF8.GetBytes(key);  
                aes.IV = iv;  
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);  
  
                using (MemoryStream memoryStream = new MemoryStream(buffer))  
                {  
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))  
                    {  
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))  
                        {  
                            return streamReader.ReadToEnd();  
                        }  
                    }  
                }  
            }  
        } 

    }

    class Program
    {
        
        static void Main(string[] args)
        {   


            EncrFactory eFactory = null; 
            DecrFactory dFactory = null; 
            EncryptedJson json = new EncryptedJson();



            Console.Write("Please choose '1'(for encryption) or '2'(for decryption): ");
            string chosenAction = Console.ReadLine();
            if (chosenAction == "1")
            {
                Console.Write("Please choose '1'(for assymetric) or '2'(for symmetric) encryption: ");
                string chosenType = Console.ReadLine();
                Console.Write("Path of data you want to encrypt: ");
                string dataFilePath = Console.ReadLine();
                string rawData = json.FileToString(dataFilePath);
                Console.Write("File name to save encrypted data to: ");
                string encrFile = Console.ReadLine();
                Console.WriteLine();

                eFactory = new Encryption(chosenType, rawData, encrFile);

                Encr encr = eFactory.GetEncr(); 
            }
            else
            {
                Console.Write("Path of data you want to decrypt: ");
                string dataFilePath = Console.ReadLine();

                EncryptedJson encrInfo = json.LoadJson(dataFilePath);

                dFactory = new Decryption(dataFilePath);

                Decr decr = dFactory.GetDecr(); 

            }

            Console.WriteLine();
            Console.Write("Press any key to continue.");
            Console.ReadKey();  




            
            

        }

    }
}
