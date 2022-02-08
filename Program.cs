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
    abstract class Encryption{
        public abstract string Type { get; set;}
        public abstract string Data { get; set; }
        public abstract string EncrFileName { get; set; }

    }

    abstract class EncryptionFactory{
        public abstract Encryption GetEncryption();
    }

    class AssymmetricEncryptionFactory : EncryptionFactory
    {
        private string _type;
        private string _data;  
        private string _encrFileName;  
  
        public AssymmetricEncryptionFactory(string type, string data, string encrFileName)  
        {  
            _type = type;
            _data = data;  
            _encrFileName = encrFileName;  
        }  
  
        public override Encryption GetEncryption()  
        {  
            return new AssymmetricEncryption(_type, _data, _encrFileName);  
        }  

    }

    class AssymmetricEncryption : Encryption{

        private string _type;
        private string _data;
        private string _encrFileName;

        public AssymmetricEncryption(string type, string data, string encrFileName)
        {
            _type = type;
            _encrFileName = encrFileName;

            EncryptedJson json = new EncryptedJson();

            var asymKeys = GenerateAssymetricKeys();
            string publicKey = asymKeys.Item1;
            string privateKey = asymKeys.Item2;
            Console.WriteLine("Public key: ");
            Console.WriteLine(publicKey);
            Console.WriteLine("Private key: ");
            Console.WriteLine(privateKey);

            var dataToEncrypt = Encrypt(publicKey, data);

            _data = dataToEncrypt;

            json.EncodedJson(type, publicKey, dataToEncrypt, encrFileName);

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

        public string Encrypt(string publicKey, string data)
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

    }

    class SymmetricEncryptionFactory : EncryptionFactory
    {
        private string _type;
        private string _data;  
        private string _encrFileName;  
  
        public SymmetricEncryptionFactory(string type, string data, string encrFileName)  
        {  
            _type = type;
            _data = data;  
            _encrFileName = encrFileName;  
        }  
  
        public override Encryption GetEncryption()  
        {  
            return new SymmetricEncryption(_type, _data, _encrFileName);  
        }  

    }
    class SymmetricEncryption : Encryption{

        
        private string _type;
        private string _data;
        private string _encrFileName;

        public SymmetricEncryption(string type, string data, string encrFileName)
        {
            _type = type;
            _encrFileName = encrFileName;
            EncryptedJson json = new EncryptedJson();

            var key = ConvertCryptoKeyToStr(GenerateCryptoKey());  

            Console.WriteLine();
            Console.WriteLine("Symmetric Key: ");
            Console.WriteLine(key);
            Console.WriteLine();

            var dataToEncrypt = Encrypt(key, data);  
            var hash = GenerateHash(data);
            _data = dataToEncrypt;

            json.EncodedJson(type, hash, dataToEncrypt, encrFileName);


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
        public string Encrypt(string key, string data)  
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
    abstract class Decryption{
        public abstract string Key { get; set; }
        public abstract string EncrFileName { get; set; }

    }

    abstract class DecryptionFactory{
        public abstract Decryption GetDecryption();
    }

    class AssymmetricDecryptionFactory : DecryptionFactory
    {
        private string _key;  
        private string _encrFileName;  
  
        public AssymmetricDecryptionFactory(string key, string encrFileName)  
        {  
            _key = key;  
            _encrFileName = encrFileName;  
        }  
  
        public override Decryption GetDecryption()  
        {  
            return new AssymmetricDecryption(_key, _encrFileName);  
        } 

    }

    class AssymmetricDecryption : Decryption{

        private string _key;
        private string _encrFileName;

        public AssymmetricDecryption(string key, string encrFileName)
        {
            // * DECRYPTING - Assymmetric

            EncryptedJson json = new EncryptedJson();

            EncryptedJson encrInfo = json.LoadJson(encrFileName);
            string publicKey_decr = encrInfo.jHash;
            string e_decr = encrInfo.jData;

            var decrMessage = Decrypt(e_decr, key);
            Console.WriteLine();
            Console.WriteLine("Decrypted message: " + decrMessage);

        }

        public override string Key 
        { 
            get {return _key; }
            set {_key = value;} 
        }

        public override string EncrFileName
        {
            get {return _encrFileName; }
            set {_encrFileName = value;} 
        }

        public string Decrypt(string cipherText, string privateKey)
        {

            using (var rsa = new RSACryptoServiceProvider())
            {
                var cipherByteData = Convert.FromBase64String(cipherText);
                rsa.FromXmlString(privateKey); 

                var encryptData = rsa.Decrypt(cipherByteData, false);
                return Encoding.UTF8.GetString(encryptData);
            }
        }

    }

    class SymmetricDecryptionFactory : DecryptionFactory
    {
        private string _key;  
        private string _encrFileName;  
  
        public SymmetricDecryptionFactory(string key, string encrFileName)  
        {  
            _key = key;  
            _encrFileName = encrFileName;  
        }  
  
        public override Decryption GetDecryption()  
        {  
            return new SymmetricDecryption(_key, _encrFileName);  
        }  

    }
    class SymmetricDecryption : Decryption{

        private string _key;
        private string _encrFileName;

        public SymmetricDecryption(string key, string encrFileName)
        {
            _encrFileName = encrFileName;
            EncryptedJson json = new EncryptedJson();

            EncryptedJson encrInfo = json.LoadJson(encrFileName);

            string h_decr = encrInfo.jHash;
            string e_decr = encrInfo.jData;
            

            string decrypted_e = Decrypt(key, e_decr);
            string h1 = GenerateHash(decrypted_e);

            if (string.Equals(h_decr, h1))
            {
                Console.WriteLine();
                Console.WriteLine("Decrypted Message: " + decrypted_e);
            }


        }

        public override string Key 
        { 
            get {return _key; }
            set {_key = value;} 
        }

        public override string EncrFileName
        {
            get {return _encrFileName; }
            set {_encrFileName = value;} 
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
  
        public string Decrypt(string key, string cipherText)  
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


            EncryptionFactory eFactory = null; 
            DecryptionFactory dFactory = null; 
            EncryptedJson json = new EncryptedJson();



            Console.Write("Please choose '1'(for encryption) or '2'(for decription): ");
            string chosenAction = Console.ReadLine();
            if (chosenAction == "1")
            {
                Console.Write("Please choose '1'(for assimetric) or '2'(for symmetric) encryption: ");
                string chosenType = Console.ReadLine();
                Console.Write("Path of data you want to encrypt: ");
                string dataFilePath = Console.ReadLine();
                string rawData = json.FileToString(dataFilePath);
                Console.Write("File name to save encrypted data to: ");
                string encrFile = Console.ReadLine();
                Console.WriteLine();


                switch (chosenType){
                case "1":
                    eFactory = new AssymmetricEncryptionFactory(chosenType, rawData, encrFile);
                    break;
                
                case "2":
                    eFactory = new SymmetricEncryptionFactory(chosenType, rawData, encrFile);
                    break;

                default:
                    break;

                }

                Encryption encr = eFactory.GetEncryption(); 
            }
            else
            {
                Console.Write("Path of data you want to decrypt: ");
                string dataFilePath = Console.ReadLine();

                EncryptedJson encrInfo = json.LoadJson(dataFilePath);

                switch (encrInfo.jType.ToString()){
                case "1":
                    Console.Write("Private key: ");
                    string privateKey = Console.ReadLine();
                    dFactory = new AssymmetricDecryptionFactory(privateKey, dataFilePath);
                    break;
                
                case "2":
                    Console.Write("Symmetric key: ");
                    string key = Console.ReadLine();
                    dFactory = new SymmetricDecryptionFactory(key, dataFilePath);
                    break;

                default:
                    break;

                }

                Decryption decr = dFactory.GetDecryption(); 


            }

            Console.ReadKey();  




            
            

        }

    }
}
