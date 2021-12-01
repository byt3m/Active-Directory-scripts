using System.Security.Cryptography;

namespace PasswordGenerator
{
	public class Generator
	{
		private static readonly RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

		public static string getRandomPassword(uint pwdLength)
		{
			string text = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789!|\"#$%&/()=?¿¡'*+-^-_.:,;\\";
			string text2 = "";
			while (text2.Length != pwdLength)
			{
				byte[] array = new byte[1];
				Generator.rngCsp.GetBytes(array);
				if ((int)array[0] < text.Length)
				{
					text2 += text[(int)array[0]].ToString();
				}
			}
			return text2;
		}
	}
}
