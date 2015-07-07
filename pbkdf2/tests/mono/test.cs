using System;
using System.Text;
using System.Security.Cryptography;

class Test
{
  static void Main()
  {
    var salt = Encoding.UTF8.GetBytes("saltsalt");
    var iterations = 1 << 22;
    Rfc2898DeriveBytes v = new Rfc2898DeriveBytes("password", salt, iterations);
    var k = v.GetBytes(20);
    System.Console.WriteLine("SHA1," + iterations + "," + BitConverter.ToString(k).Replace("-", string.Empty));
  }
}
