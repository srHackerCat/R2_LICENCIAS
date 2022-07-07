using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Caching;
using System.Xml;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using YamlDotNet.Serialization;
using MyCompany.Services;
using MyCompany.Services.Rest;

namespace MyCompany.Data
{
    public class SelectClauseDictionary : SortedDictionary<string, string>
    {

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private bool _trackAliases;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private List<string> _referencedAliases;

        public bool TrackAliases
        {
            get
            {
                return _trackAliases;
            }
            set
            {
                _trackAliases = value;
            }
        }

        public List<string> ReferencedAliases
        {
            get
            {
                return _referencedAliases;
            }
            set
            {
                _referencedAliases = value;
            }
        }

        public new string this[string name]
        {
            get
            {
                string expression = null;
                if (!TryGetValue(name.ToLower(), out expression))
                    expression = "null";
                else
                {
                    if (TrackAliases)
                    {
                        var m = Regex.Match(expression, "^('|\"|\\[|`)(?\'Alias\'.+?)(\'|\"|\\]|`)");
                        if (m.Success)
                        {
                            if (ReferencedAliases == null)
                                ReferencedAliases = new List<string>();
                            var aliasName = m.Groups["Alias"].Value;
                            if (m.Success && !ReferencedAliases.Contains(aliasName))
                                ReferencedAliases.Add(aliasName);
                        }
                    }
                }
                return expression;
            }
            set
            {
                base[name.ToLower()] = value;
            }
        }

        public new bool ContainsKey(string name)
        {
            return base.ContainsKey(name.ToLower());
        }

        public new void Add(string key, string value)
        {
            base.Add(key.ToLower(), value);
        }

        public new bool TryGetValue(string key, out string value)
        {
            return base.TryGetValue(key.ToLower(), out value);
        }
    }

    public interface IDataController
    {

        ViewPage GetPage(string controller, string view, PageRequest request);

        object[] GetListOfValues(string controller, string view, DistinctValueRequest request);

        ActionResult Execute(string controller, string view, ActionArgs args);
    }

    public interface IAutoCompleteManager
    {

        string[] GetCompletionList(string prefixText, int count, string contextKey);
    }

    public interface IActionHandler
    {

        void BeforeSqlAction(ActionArgs args, ActionResult result);

        void AfterSqlAction(ActionArgs args, ActionResult result);

        void ExecuteAction(ActionArgs args, ActionResult result);
    }

    public interface IRowHandler
    {

        bool SupportsNewRow(PageRequest requet);

        void NewRow(PageRequest request, ViewPage page, object[] row);

        bool SupportsPrepareRow(PageRequest request);

        void PrepareRow(PageRequest request, ViewPage page, object[] row);
    }

    public interface IDataFilter
    {

        void Filter(SortedDictionary<string, object> filter);
    }

    public interface IDataFilter2
    {

        void Filter(string controller, string view, SortedDictionary<string, object> filter);

        void AssignContext(string controller, string view, string lookupContextController, string lookupContextView, string lookupContextFieldName);
    }

    public interface IDataEngine
    {

        DbDataReader ExecuteReader(PageRequest request);
    }

    public interface IPlugIn
    {

        ControllerConfiguration Config
        {
            get;
            set;
        }

        ControllerConfiguration Create(ControllerConfiguration config);

        void PreProcessPageRequest(PageRequest request, ViewPage page);

        void ProcessPageRequest(PageRequest request, ViewPage page);

        void PreProcessArguments(ActionArgs args, ActionResult result, ViewPage page);

        void ProcessArguments(ActionArgs args, ActionResult result, ViewPage page);
    }

    public class BusinessObjectParameters : SortedDictionary<string, object>
    {

        private string _parameterMarker = null;

        public BusinessObjectParameters()
        {
        }

        public BusinessObjectParameters(params object[] values)
        {
            Assign(values);
        }

        public static BusinessObjectParameters Create(string parameterMarker, params object[] values)
        {
            var paramList = new BusinessObjectParameters()
            {
                _parameterMarker = parameterMarker
            };
            paramList.Assign(values);
            return paramList;
        }

        public void Assign(params object[] values)
        {
            var parameterMarker = _parameterMarker;
            for (var i = 0; (i < values.Length); i++)
            {
                var v = values[i];
                if (v is FieldValue)
                {
                    var fv = ((FieldValue)(v));
                    Add(fv.Name, fv.Value);
                }
                else
                {
                    if (v is SortedDictionary<string, object>)
                    {
                        var paramList = ((SortedDictionary<string, object>)(v));
                        foreach (var name in paramList.Keys)
                        {
                            var paramName = name;
                            if (!Char.IsLetterOrDigit(paramName[0]) && !string.IsNullOrEmpty(parameterMarker))
                                paramName = (parameterMarker + paramName.Substring(1));
                            Add(paramName, paramList[name]);
                        }
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(parameterMarker))
                            parameterMarker = SqlStatement.GetParameterMarker(string.Empty);
                        if ((v != null) && (v.GetType().Namespace == null))
                            foreach (var pi in v.GetType().GetProperties())
                                Add((parameterMarker + pi.Name), pi.GetValue(v));
                        else
                            Add((parameterMarker + ("p" + i.ToString())), v);
                    }
                }
            }
        }

        public string ToWhere()
        {
            var filterExpression = new StringBuilder();
            foreach (var paramName in Keys)
            {
                if (filterExpression.Length > 0)
                    filterExpression.Append("and");
                var v = this[paramName];
                if (DBNull.Value.Equals(v) || (v == null))
                    filterExpression.AppendFormat("({0} is null)", paramName.Substring(1));
                else
                    filterExpression.AppendFormat("({0}={1})", paramName.Substring(1), paramName);
            }
            return filterExpression.ToString();
        }
    }

    public interface IBusinessObject
    {

        void AssignFilter(string filter, BusinessObjectParameters parameters);
    }

    public enum CommandConfigurationType
    {

        Select,

        Update,

        Insert,

        Delete,

        SelectCount,

        SelectDistinct,

        SelectAggregates,

        SelectFirstLetters,

        SelectExisting,

        Sync,

        None,
    }

    public class TextUtility
    {

        private static char[] _chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

        public static byte[] HexToByte(string hexString)
        {
            var returnBytes = new byte[(hexString.Length / 2)];
            for (var i = 0; (i < returnBytes.Length); i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring((i * 2), 2), 16);
            return returnBytes;
        }

        public static string Hash(byte[] data)
        {
            var theHash = new HMACSHA1()
            {
                Key = HexToByte(ApplicationServices.ValidationKey)
            };
            var hashedText = Convert.ToBase64String(theHash.ComputeHash(data));
            return hashedText;
        }

        public static string Hash(string text)
        {
            if (string.IsNullOrEmpty(text))
                return text;
            return Hash(Encoding.UTF8.GetBytes(text));
        }

        public static byte[] ComputeS256Hash(string text)
        {
            if (string.IsNullOrEmpty(text))
                return null;
            using (var theSHA256 = SHA256.Create())
                return theSHA256.ComputeHash(Encoding.UTF8.GetBytes(text));
        }

        public static string ToBase32String(string s)
        {
            return ToBase32String(Encoding.UTF8.GetBytes(s));
        }

        public static string ToBase32String(byte[] input)
        {
            // https://datatracker.ietf.org/doc/html/rfc4648
            if ((input == null) || (input.Length == 0))
                throw new ArgumentNullException("input");
            var charCount = ((int)((Math.Ceiling((input.Length / ((double)(5)))) * 8)));
            var returnArray = new char[charCount];
            byte nextChar = 0;
            byte bitsRemaining = 5;
            byte arrayIndex = 0;
            foreach (byte b in input)
            {
                nextChar = ((byte)((nextChar | (b >> (8 - bitsRemaining)))));
                returnArray[arrayIndex] = ByteToBase32Char(nextChar);
                arrayIndex++;
                if (bitsRemaining < 4)
                {
                    nextChar = ((byte)(((b >> (3 - bitsRemaining)) & 31)));
                    returnArray[arrayIndex] = ByteToBase32Char(nextChar);
                    arrayIndex++;
                    bitsRemaining = ((byte)((bitsRemaining + 5)));
                }
                bitsRemaining = ((byte)((bitsRemaining - 3)));
                nextChar = ToByte(((b << bitsRemaining) & 31));
            }
            // if we didn't end with a full char
            if (arrayIndex != charCount)
            {
                returnArray[arrayIndex] = ByteToBase32Char(nextChar);
                arrayIndex++;
                while (arrayIndex != charCount)
                {
                    returnArray[arrayIndex] = '=';
                    arrayIndex++;
                }
            }
            return new string(returnArray);
        }

        protected static byte ToByte(int i)
        {
            return BitConverter.GetBytes(i)[0];
        }

        public static byte[] FromBase32String(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException("input");
            input = input.Trim('=');
            var byteCount = ((input.Length * 5) / 8);
            var returnArray = new byte[byteCount];
            byte curByte = 0;
            byte bitsRemaining = 8;
            int mask;
            var arrayIndex = 0;
            foreach (var c in input)
            {
                var cValue = CharToValue(c);
                if (bitsRemaining > 5)
                {
                    mask = (cValue << (bitsRemaining - 5));
                    curByte = ((byte)((curByte | mask)));
                    bitsRemaining = ((byte)((bitsRemaining - 5)));
                }
                else
                {
                    mask = (cValue >> (5 - bitsRemaining));
                    curByte = ((byte)((curByte | mask)));
                    returnArray[arrayIndex] = curByte;
                    arrayIndex++;
                    curByte = ToByte((cValue << (3 + bitsRemaining)));
                    bitsRemaining = ((byte)((bitsRemaining + 3)));
                }
            }
            if (arrayIndex != byteCount)
                returnArray[arrayIndex] = curByte;
            return returnArray;
        }

        public static int CharToValue(char c)
        {
            var value = Convert.ToInt32(c);
            // 65-90 == uppercase letters
            if ((value < 91) && (value > 64))
                return (value - 65);
            // 50-55 == numbers 2-7
            if ((value < 56) && (value > 49))
                return (value - 24);
            // 97-122 == lowercase letters
            if ((value < 123) && (value > 96))
                return (value - 97);
            throw new ArgumentException("Character is not a Base32 character.", "c");
        }

        public static char ByteToBase32Char(byte b)
        {
            if (b < 26)
                return Convert.ToChar((b + 65));
            if (b < 32)
                return Convert.ToChar((b + 24));
            throw new ArgumentException("Byte is not a value Base32 value.", "b");
        }

        public static string XmlToJson(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return JsonConvert.SerializeXmlNode(doc.ChildNodes[0], Newtonsoft.Json.Formatting.Indented, true);
        }

        public static JObject ParseYamlOrJson(string yamlOrJson)
        {
            return ParseYamlOrJson(yamlOrJson, false);
        }

        public static JObject ParseYamlOrJson(string yamlOrJson, bool throwError)
        {
            if (string.IsNullOrWhiteSpace(yamlOrJson))
                return null;
            try
            {
                if (Regex.IsMatch(yamlOrJson, "^\\s*\\{"))
                    return JObject.Parse(yamlOrJson);
                var yamlObject = new DeserializerBuilder().Build().Deserialize(new StringReader(yamlOrJson));
                var json = new SerializerBuilder().JsonCompatible().Build().Serialize(yamlObject);
                json = Regex.Replace(json, ": \"(true|True|TRUE|false|False|FALSE)\"", YamlBooleanToJSON);
                return JObject.Parse(json);
            }
            catch (Exception ex)
            {
                if (throwError)
                    throw ex;
                return new JObject(new JProperty("error", ex.Message));
            }
        }

        private static string YamlBooleanToJSON(Match m)
        {
            return (": " + m.Groups[1].Value.ToLower());
        }

        public static object JsonToYaml(JToken token)
        {
            if (token is JValue)
                return ((JValue)(token)).Value;
            if (token is JArray)
                return token.AsEnumerable().Select(JsonToYaml).ToList();
            if (token is JObject)
                return token.AsEnumerable().Cast<JProperty>().ToDictionary(JTokenToString, JTokenToYaml);
            throw new InvalidOperationException(("Unexpected token:" + Convert.ToString(token)));
        }

        private static string JTokenToString(JProperty x)
        {
            return x.Name;
        }

        private static object JTokenToYaml(JProperty x)
        {
            return JsonToYaml(x.Value);
        }

        public static string ToYamlString(JObject json)
        {
            var stringWriter = new StringWriter();
            var serializer = new YamlDotNet.Serialization.Serializer();
            serializer.Serialize(stringWriter, JsonToYaml(json));
            var output = stringWriter.ToString();
            if (string.IsNullOrEmpty(output) || (output.ToString().Trim() == "{}"))
                output = null;
            return output;
        }

        public static string GetUniqueKey(int size)
        {
            return GetUniqueKey(size, null);
        }

        public static string GetUniqueKey(int size, string charsAlt)
        {
            var chars = _chars;
            if (!string.IsNullOrEmpty(charsAlt))
                chars = charsAlt.ToCharArray();
            var data = new byte[(4 * size)];
            using (var crypto = new RNGCryptoServiceProvider())
                crypto.GetBytes(data);
            var result = new StringBuilder(size);
            for (var i = 0; (i < size); i++)
            {
                var rnd = BitConverter.ToUInt32(data, (i * 4));
                var idx = (rnd % chars.Length);
                result.Append(chars[idx]);
            }
            return result.ToString();
        }

        public static string ToUrlEncodedToken(string text)
        {
            return ToBase64UrlEncoded(ComputeS256Hash(text));
        }

        public static string ToBase64UrlEncoded(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static byte[] FromBase64UrlEncoded(string text)
        {
            text = text.Replace('_', '/').Replace('-', '+');
            var padding = string.Empty;
            var paddingSize = (text.Length % 4);
            if (paddingSize == 2)
                padding = "==";
            if (paddingSize == 3)
                padding = "=";
            return Convert.FromBase64String((text + padding));
        }

        public static string CreateJwt(JObject claims)
        {
            var jwtHeader = new JObject(new JProperty("typ", "JWT"), new JProperty("alg", "HS256"));
            var jwt = string.Format("{0}.{1}", ToBase64UrlEncoded(Encoding.UTF8.GetBytes(jwtHeader.ToString(Newtonsoft.Json.Formatting.None, null))), ToBase64UrlEncoded(Encoding.UTF8.GetBytes(claims.ToString(Newtonsoft.Json.Formatting.None, null))));
            var secret = Encoding.UTF8.GetBytes(ApplicationServices.ValidationKey);
            using (var hmacSha256 = new HMACSHA256(secret))
            {
                var dataToHmac = Encoding.UTF8.GetBytes(jwt);
                jwt = string.Format("{0}.{1}", jwt, ToBase64UrlEncoded(hmacSha256.ComputeHash(dataToHmac)));
            }
            return jwt;
        }

        public static bool ValidateJwt(string token)
        {
            var jwt = token.Split('.');
            if (jwt.Length != 3)
                return false;
            var newToken = string.Format("{0}.{1}", jwt[0], jwt[1]);
            var secret = Encoding.UTF8.GetBytes(ApplicationServices.ValidationKey);
            using (var hmacSha256 = new HMACSHA256(secret))
            {
                var dataToHmac = Encoding.UTF8.GetBytes(newToken);
                newToken = string.Format("{0}.{1}", newToken, ToBase64UrlEncoded(hmacSha256.ComputeHash(dataToHmac)));
            }
            return (token == newToken);
        }
    }

    public class FolderCacheDependency : CacheDependency
    {

        private FileSystemWatcher _watcher;

        public FolderCacheDependency(string dirName, string filter)
        {
            _watcher = new FileSystemWatcher(dirName, filter)
            {
                EnableRaisingEvents = true
            };
            _watcher.Changed += new FileSystemEventHandler(this.watcher_Changed);
            _watcher.Deleted += new FileSystemEventHandler(this.watcher_Changed);
            _watcher.Created += new FileSystemEventHandler(this.watcher_Changed);
            _watcher.Renamed += new RenamedEventHandler(this.watcher_Renamed);
        }

        void watcher_Renamed(object sender, RenamedEventArgs e)
        {
            NotifyDependencyChanged(this, e);
        }

        void watcher_Changed(object sender, FileSystemEventArgs e)
        {
            NotifyDependencyChanged(this, e);
        }
    }

    public class Totp
    {

        private long _unixEpochTicks = Convert.ToInt64("621355968000000000");

        private long _ticksToSeconds = 10000000;

        private int _step;

        private byte[] _key;

        public Totp(string secretKey, int period) :
                this(Encoding.UTF8.GetBytes(secretKey), period)
        {
        }

        public Totp(byte[] secretKey, int period)
        {
            _key = secretKey;
            _step = period;
        }

        public string Compute()
        {
            return Compute(DateTime.UtcNow);
        }

        public string Compute(DateTime date)
        {
            return Compute(date, 6);
        }

        public string Compute(DateTime date, int totpSize)
        {
            var window = CalculateTimeStepFromTimestamp(date);
            var data = GetBigEndianBytes(window);
            var hmac = new HMACSHA1()
            {
                Key = _key
            };
            var hmacComputedHash = hmac.ComputeHash(data);
            var offset = (hmacComputedHash[(hmacComputedHash.Length - 1)] & 15);
            var otp = ((hmacComputedHash[offset] & 127) << 24);
            otp = (otp | ((hmacComputedHash[(offset + 1)] & 255) << 16));
            otp = (otp | ((hmacComputedHash[(offset + 2)] & 255) << 8));
            otp = (otp | ((hmacComputedHash[(offset + 3)] & 255) % 1000000));
            var result = Digits(otp, totpSize);
            return result;
        }

        public string[] Compute(int totpSize, int count)
        {
            var d = new DateTime(1995, 1, 1);
            var range = (DateTime.Today - d).Days;
            d = d.AddDays(new Random().Next(range));
            var list = new List<string>();
            for (var i = 0; (i < count); i++)
                list.Add(Compute(d.AddSeconds((_step * i)), totpSize));
            return list.ToArray();
        }

        public int RemainingSeconds()
        {
            return (_step - ((int)((((DateTime.UtcNow.Ticks - _unixEpochTicks) / _ticksToSeconds) % _step))));
        }

        private byte[] GetBigEndianBytes(long input)
        {
            var data = BitConverter.GetBytes(input);
            Array.Reverse(data);
            return data;
        }

        long CalculateTimeStepFromTimestamp(DateTime timestamp)
        {
            var unixTimestamp = ((timestamp.Ticks - _unixEpochTicks) / _ticksToSeconds);
            var window = (unixTimestamp / ((long)(_step)));
            return window;
        }

        private string Digits(long input, int digitCount)
        {
            var truncateValue = (((int)(input)) % ((int)(Math.Pow(10, digitCount))));
            return truncateValue.ToString().PadLeft(digitCount, '0');
        }
    }

    public class DataCacheItem
    {

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _controller;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private int _duration;

        private long _maxAge;

        [System.Diagnostics.DebuggerBrowsable(System.Diagnostics.DebuggerBrowsableState.Never)]
        private string _key;

        private object _value;

        public DataCacheItem(string controller) :
                this(controller, null)
        {
        }

        public DataCacheItem(string controller, object request)
        {
            this.Controller = controller;
            if (!string.IsNullOrEmpty(controller) && !ApplicationServices.Create().IsSystemController(controller))
            {
                var rules = ((JObject)(ApplicationServicesBase.SettingsProperty("server.cache.rules")));
                if (rules != null)
                {
                    // test the exemptions
                    foreach (var p in rules.Properties())
                        try
                        {
                            var re = new Regex(p.Name, RegexOptions.IgnoreCase);
                            if (re.IsMatch(controller))
                            {
                                if (RESTfulResource.LatestVersion == controller)
                                    break;
                                else
                                    Duration = Convert.ToInt32((Convert.ToDouble(p.Value["duration"]) * 60));
                                if (IsMatch)
                                {
                                    var exempt = Convert.ToString(p.Value["exemptRoles"]);
                                    if (!string.IsNullOrEmpty(exempt))
                                    {
                                        var exemptRoles = Regex.Split(exempt, "\\s*,\\s*");
                                        foreach (var role in exemptRoles)
                                            if (HttpContext.Current.User.IsInRole(role))
                                            {
                                                Duration = 0;
                                                break;
                                            }
                                    }
                                }
                                if (IsMatch)
                                {
                                    var exempt = Convert.ToString(p.Value["exemptScopes"]);
                                    if (!string.IsNullOrEmpty(exempt))
                                    {
                                        var exemptScopes = Regex.Split(exempt, "\\s+");
                                        if (exemptScopes.Length > 0)
                                        {
                                            var userScopes = RESTfulResource.Scopes;
                                            foreach (var scope in exemptScopes)
                                                if (userScopes.Contains(scope))
                                                {
                                                    Duration = 0;
                                                    break;
                                                }
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // do nothing
                        }
                    // fetch from cache if there is a match to the request
                    if (IsMatch && (request != null))
                    {
                        var json = JsonConvert.SerializeObject(request);
                        var hash = TextUtility.ToUrlEncodedToken(json);
                        Key = string.Format("data-cache/{0}/{1}", controller.ToLower(), hash);
                        var cachedData = ((object[])(HttpContext.Current.Cache[Key]));
                        if (cachedData != null)
                        {
                            _value = cachedData[0];
                            _maxAge = (Duration - TimeSpan.FromTicks((DateTime.Now.Ticks - ((DateTime)(cachedData[1])).Ticks)).Seconds);
                        }
                    }
                }
            }
        }

        public string Controller
        {
            get
            {
                return _controller;
            }
            set
            {
                _controller = value;
            }
        }

        public int Duration
        {
            get
            {
                return _duration;
            }
            set
            {
                _duration = value;
            }
        }

        public long MaxAge
        {
            get
            {
                if (_value == null)
                    return Duration;
                return _maxAge;
            }
        }

        public string Key
        {
            get
            {
                return _key;
            }
            set
            {
                _key = value;
            }
        }

        public object Value
        {
            get
            {
                return _value;
            }
            set
            {
                if (IsMatch)
                    try
                    {
                        if (!((value is JObject)) || (((JObject)(value))["error"] == null))
                        {
                            _value = value;
                            _maxAge = Duration;
                            HttpContext.Current.Cache.Add(Key, new object[] {
                                        _value,
                                        DateTime.Now}, null, DateTime.Now.AddSeconds(Duration), Cache.NoSlidingExpiration, CacheItemPriority.Normal, null);
                        }
                    }
                    catch (Exception)
                    {
                        // ignore the possible dupicates in the cache that may be created under the high load
                    }
            }
        }

        public bool IsMatch
        {
            get
            {
                return (Duration > 0);
            }
        }

        public bool HasValue
        {
            get
            {
                return (IsMatch && (Value != null));
            }
        }

        public virtual void SetMaxAge()
        {
            var response = HttpContext.Current.Response;
            response.Cookies.Clear();
            if (RESTfulResource.PublicApiKey != null)
            {
                response.Cache.SetCacheability(HttpCacheability.Public);
                response.Cache.SetProxyMaxAge(TimeSpan.FromSeconds(MaxAge));
            }
            response.Cache.SetMaxAge(TimeSpan.FromSeconds(MaxAge));
        }
    }
}
