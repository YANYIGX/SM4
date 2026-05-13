using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System;

namespace SM4
{
   
    public class SM4Helper
    {
        private readonly SM4ModeWrapper _wrapper;

     
        public SM4Helper(byte[] key,
            SM4Mode mode = SM4Mode.ECB,
            SM4Padding padding = SM4Padding.PKCS7, byte[] iv = null)
        {
            _wrapper = new SM4ModeWrapper(key, mode, padding, iv);
        }

      
        public byte[] Encrypt(byte[] data) => _wrapper.Encrypt(data);

       
        public byte[] Decrypt(byte[] data) => _wrapper.Decrypt(data);

     
        public string EncryptString(string plainText)
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes(plainText);
            byte[] encrypted = Encrypt(data);
            return Convert.ToBase64String(encrypted);
        }

  
        public string DecryptString(string cipherText)
        {
            byte[] data = Convert.FromBase64String(cipherText);
            byte[] decrypted = Decrypt(data);
            return System.Text.Encoding.UTF8.GetString(decrypted);
        }

      
        public SM4ModeWrapper GetModeWrapper() => _wrapper;
    }

  
  
}
