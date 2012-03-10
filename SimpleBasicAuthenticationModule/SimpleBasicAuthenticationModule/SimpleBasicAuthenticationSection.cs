using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace Misuzilla.Web.Configuration
{
    public class SimpleBasicAuthenticationSection : ConfigurationSection
    {
        public const String SectionName = "misuzilla.web/basicAuthentication";
        
        [ConfigurationProperty("enabled", DefaultValue = true)]
        public Boolean Enabled
        {
            get { return (Boolean)this["enabled"]; }
        }

        [ConfigurationProperty("setUser", DefaultValue = true)]
        public Boolean SetUser
        {
            get { return (Boolean)this["setUser"]; }
        }

        [ConfigurationProperty("realm", DefaultValue = "Authentication Required")]
        public String Realm
        {
            get { return (String)this["realm"]; }
            set { this["realm"] = value; }
        }
        
        [ConfigurationProperty("users")]
        public SimpleBasicAuthenticationUserElementCollection Users
        {
            get { return this["users"] as SimpleBasicAuthenticationUserElementCollection; }
        }
        
        [ConfigurationProperty("exceptPaths")]
        public SimpleBasicAuthenticationExceptPathsElementCollection ExceptPaths
        {
            get { return this["exceptPaths"] as SimpleBasicAuthenticationExceptPathsElementCollection; }
        }
    }
    
    public class SimpleBasicAuthenticationUserElementCollection : ConfigurationElementCollection
    {
        public SimpleBasicAuthenticationUserElementCollection()
        {
            AddElementName = "user";
        }
        protected override ConfigurationElement CreateNewElement()
        {
            return new SimpleBasicAuthenticationUserElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return (element as SimpleBasicAuthenticationUserElement).Name;
        }
    }

    public class SimpleBasicAuthenticationUserElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsRequired = true, IsKey = true)]
        public String Name
        {
            get { return (String)this["name"]; }
            set { this["name"] = value; }
        }

        [ConfigurationProperty("password", IsRequired = true)]
        public String Password
        {
            get { return (String)this["password"]; }
            set { this["password"] = value; }
        }
    
        [ConfigurationProperty("type", DefaultValue = PasswordEncodeType.ClearText)]
        public PasswordEncodeType Type
        {
            get { return (PasswordEncodeType)this["type"]; }
            set { this["type"] = value; }
        }
    
        [ConfigurationProperty("roles")]
        public String Roles
        {
            get { return (String)this["roles"]; }
            set { this["roles"] = value; }
        }
    }

    public class SimpleBasicAuthenticationExceptPathsElementCollection : ConfigurationElementCollection
    {
        public SimpleBasicAuthenticationExceptPathsElementCollection()
        {
            AddElementName = "exceptPath";
        }
        protected override ConfigurationElement CreateNewElement()
        {
            return new SimpleBasicAuthenticationExceptPathElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return (element as SimpleBasicAuthenticationExceptPathElement).Path;
        }
    }

    public class SimpleBasicAuthenticationExceptPathElement : ConfigurationElement
    {
        [ConfigurationProperty("path", IsRequired = true, IsKey = true)]
        public String Path
        {
            get { return (String)this["path"]; }
            set { this["path"] = value; }
        }

        [ConfigurationProperty("useRegex")]
        public Boolean UseRegex
        {
            get { return (Boolean)this["useRegex"]; }
            set { this["useRegex"] = value; }
        }
    }

    public enum PasswordEncodeType
    {
        ClearText,
        MD5,
        SHA1
    }
}
