using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Security;
using Newtonsoft.Json.Linq;

namespace MyCompany.Services.Rest
{
    public class SaasConfiguration
    {

        private string _config;

        private string _clientId;

        private string _clientSecret;

        private string _redirectUri;

        private string _accessToken;

        private string _refreshToken;

        public SaasConfiguration(string config)
        {
            _config = (("\n" + config) + "\n");
        }

        public virtual string ClientId
        {
            get
            {
                if (string.IsNullOrEmpty(_clientId))
                    _clientId = this["Client Id"];
                return _clientId;
            }
        }

        public virtual string ClientSecret
        {
            get
            {
                if (string.IsNullOrEmpty(_clientSecret))
                    _clientSecret = this["Client Secret"];
                return _clientSecret;
            }
        }

        public virtual string RedirectUri
        {
            get
            {
                if (string.IsNullOrEmpty(_redirectUri))
                {
                    if ((SaasConfigManager.Instance != null) && SaasConfigManager.Instance.IsLocalRequest)
                        _redirectUri = this["Local Redirect Uri"];
                }
                if (string.IsNullOrEmpty(_redirectUri))
                    _redirectUri = this["Redirect Uri"];
                return _redirectUri;
            }
        }

        public virtual string AccessToken
        {
            get
            {
                if (string.IsNullOrEmpty(_accessToken))
                    _accessToken = this["Access Token"];
                return _accessToken;
            }
            set
            {
                _accessToken = value;
                this["Access Token"] = value;
            }
        }

        public virtual string RefreshToken
        {
            get
            {
                if (string.IsNullOrEmpty(_refreshToken))
                    _refreshToken = this["Refresh Token"];
                return _refreshToken;
            }
            set
            {
                _refreshToken = value;
                this["Refresh Token"] = value;
            }
        }

        public virtual string this[string property]
        {
            get
            {
                if (string.IsNullOrEmpty(_config))
                    return string.Empty;
                var m = Regex.Match(_config, (("\\n(" + property) + ")\\:\\s*?\\n?(?'Value'[^\\s\\n].+?)\\n"), RegexOptions.IgnoreCase);
                if (m.Success)
                    return m.Groups["Value"].Value.Trim();
                return string.Empty;
            }
            set
            {
                if (!string.IsNullOrEmpty(_config))
                {
                    var re = new Regex(("(^|\\n)(?'Name'" + (Regex.Escape(property) + ")\\s*\\:\\s*(?'Value'.*?)(\\r?\\n|$)")), (RegexOptions.Multiline | RegexOptions.IgnoreCase));
                    var test = re.Match(_config);
                    if (string.IsNullOrEmpty(value))
                    {
                        if (test.Success)
                            _config = (_config.Substring(0, test.Groups["Name"].Index) + _config.Substring((test.Index + test.Length)));
                    }
                    else
                    {
                        if (test.Success)
                            _config = (_config.Substring(0, test.Groups["Value"].Index) + (value + _config.Substring((test.Groups["Value"].Index + test.Groups["Value"].Length))));
                        else
                            _config = string.Format("{0}\n{1}: {2}", _config.Trim(), property, value);
                    }
                }
            }
        }

        public virtual void UpdateTokens(JObject data)
        {
            var aToken = ((string)(data["access_token"]));
            if (!string.IsNullOrEmpty(aToken))
                AccessToken = aToken;
            var rToken = ((string)(data["refresh_token"]));
            if (!string.IsNullOrEmpty(rToken))
                RefreshToken = rToken;
        }

        public override string ToString()
        {
            return _config;
        }
    }

    public class SaasConfigManager
    {

        private object _configLock = new object();

        public static string Location = null;

        public static SaasConfigManager Instance = new SaasConfigManager();

        private SaasConfiguration _config;

        public SaasConfigManager()
        {
        }

        public SaasConfigManager(string config)
        {
            lock (_configLock)
                _config = new SaasConfiguration(config);
        }

        public SaasConfiguration Config
        {
            get
            {
                lock (_configLock)
                    return _config;
            }
        }

        public virtual bool IsLocalRequest
        {
            get
            {
                return false;
            }
        }

        public virtual SaasConfiguration Read(RestApiClient instance)
        {
            lock (_configLock)
            {
                var config = string.Empty;
                if (!string.IsNullOrEmpty(Location))
                    config = File.ReadAllText(ToConfigFileName(instance));
                if (_config == null)
                    _config = new SaasConfiguration(config);
                return _config;
            }
        }

        public virtual void Write(RestApiClient instance, JObject data)
        {
            lock (_configLock)
            {
                _config.UpdateTokens(data);
                if (!string.IsNullOrEmpty(Location))
                    File.WriteAllText(ToConfigFileName(instance), _config.ToString());
            }
        }

        protected virtual string ToConfigFileName(RestApiClient instance)
        {
            return Path.Combine(Location, (instance.Name + ".Cofig.txt"));
        }
    }

    public partial class RestApiClient
    {

        public virtual string Name
        {
            get
            {
                var n = GetType().Name;
                if (n.EndsWith("Api", StringComparison.CurrentCulture))
                    n = n.Substring(0, (n.Length - -3));
                return n;
            }
        }
    }

    public class RESTfulResourceException : Exception
    {

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _error;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private int _httpCode;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _schemaHint;

        private List<RESTfulResourceException> _related;

        public RESTfulResourceException(string error, string description) :
                this(-1, false, error, description)
        {
        }

        public RESTfulResourceException(int httpCode, string error, string description) :
                this(httpCode, false, error, description)
        {
        }

        public RESTfulResourceException(int httpCode, bool schemaHint, string error, string description) :
                base(description)
        {
            this.HttpCode = httpCode;
            this.SchemaHint = schemaHint;
            this.Error = error;
            _related = new List<RESTfulResourceException>();
        }

        public RESTfulResourceException(List<RESTfulResourceException> errors) :
                this(errors[0].HttpCode, errors[0].SchemaHint, errors[0].Error, errors[0].Message)
        {
            for (var i = 1; (i < errors.Count); i++)
                _related.Add(errors[i]);
        }

        public string Error
        {
            get
            {
                return _error;
            }
            set
            {
                _error = value;
            }
        }

        public int HttpCode
        {
            get
            {
                return _httpCode;
            }
            set
            {
                _httpCode = value;
            }
        }

        public bool SchemaHint
        {
            get
            {
                return _schemaHint;
            }
            set
            {
                _schemaHint = value;
            }
        }

        public List<RESTfulResourceException> Related
        {
            get
            {
                return _related;
            }
        }
    }
}
