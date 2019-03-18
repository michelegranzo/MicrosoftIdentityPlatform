using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;

namespace MicrosoftIdentityPlatform.Utils
{
    public static class CustomConfigurationManager
    {
        public static NameValueCollection AppSettings { get
            {
                var collection = new NameValueCollection();
                // string text = System.IO.File.ReadAllText(@"C:\Users\miche\Documents\TEST\MicrosoftIdentityPlatform\MicrosoftIdentityPlatform\MicrosoftIdentityPlatform\settings.txt");
                string[] lines = System.IO.File.ReadAllLines(@"C:\Users\miche\Documents\TEST\MicrosoftIdentityPlatform\MicrosoftIdentityPlatform\MicrosoftIdentityPlatform\settings.txt");
                collection.Add("ClientId", lines[0].ToString().Substring(9));
                collection.Add("ClientSecret", lines[1].ToString().Substring(13));
                return collection;
            }
        }
    }
}