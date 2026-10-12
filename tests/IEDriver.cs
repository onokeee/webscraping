// IEDriver.cs -- TEST-ONLY external driver for reqrec's recording browser (reqrec/RecBrowser.cs).
//
// Lets automated tests operate the pages shown inside a running RecBrowser.exe the way a user would:
// the IE engine inside RecBrowser performs every navigation itself, so the HTTP that reaches the
// recorder is exactly the real browser's (cookies, Referer, POST bodies, popups, modal dialogs).
// This program never touches the network, the registry or any setting.
//
// How it finds the pages: EnumWindows + GetWindowThreadProcessId list the top-level windows of the
// RecBrowser process; EnumChildWindows finds every "Internet Explorer_Server" window below them
// (one per tab; showModalDialog / showModelessDialog windows live in a top-level
// "Internet Explorer_TridentDlgFrame" and are reported as kind "dialog").  The document comes from
// SendMessageTimeout(WM_HTML_GETOBJECT) + oleacc!ObjectFromLresult(IID_IHTMLDocument2) and is then
// used through plain IDispatch late binding (Type.InvokeMember; see Get/Set/Call for why not 'dynamic').
// Only DOM methods are used: execScript / eval are refused by the engine (E_ACCESSDENIED) on popup
// windows.  Frames (frameset / iframe) have no window of their own in this engine; their documents are
// reached through document.frames and reported as kind "frame" with the hwnd of the tab that holds them.
//
// Build (inbox .NET Framework 4.x, C# 5 compiler):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -target:exe -platform:x64
//       -r:System.Windows.Forms.dll -r:Microsoft.CSharp.dll -r:System.Core.dll -out:IEDriver.exe IEDriver.cs
//
// Commands (each prints exactly ONE line of JSON to stdout; exit 0 = success, 1 = failure with
// {"error": "..."}).  The JSON is pure ASCII (non-ASCII as \uXXXX), so the console code page never matters.
//   list     --pid P                                   -> [{hwnd, kind, url, title, readyState, visible, ...}]
//   wait     --pid P --url SUB [--text SUB] [--timeout S]  -> doc info once readyState == "complete"
//   value    --pid P --url SUB --id ID --value TEXT [--fire EVENT]
//   select   --pid P --url SUB --id ID (--text T | --value V)   (then fireEvent("onchange"))
//   click    --pid P --url SUB (--id ID | --link-text T | --button-text T)
//   text     --pid P --url SUB [--id ID]
//   attr     --pid P --url SUB --id ID --name NAME
//   dialog   --pid P [--title SUB] [--text SUB] [--button SUB] [--timeout S] [--method command|bmclick]
//   navigate --pid P --to URL      (types URL into RecBrowser's address box and presses Enter)
//   close    --pid P [--timeout S] (WM_CLOSE to the main window, waits for the exit code)
// navigate / close refuse while a modal dialog disables the main window (a user could not do it either).
// Common filters for the document commands: --kind tab|dialog|frame, --hwnd H; element commands retry
// until --timeout (default 10 s) while the document / element is not there yet.
//
// The language level is C# 5 (no string interpolation, nameof, ?. or expression-bodied members).
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Reqrec.Tests.IeDriver
{
    internal static class Native
    {
        public delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

        public const uint SMTO_ABORTIFHUNG = 0x0002;
        public const uint WM_GETTEXT = 0x000D;
        public const uint WM_GETTEXTLENGTH = 0x000E;
        public const uint WM_SETTEXT = 0x000C;
        public const uint WM_CLOSE = 0x0010;
        public const uint WM_COMMAND = 0x0111;
        public const uint WM_KEYDOWN = 0x0100;
        public const uint WM_KEYUP = 0x0101;
        public const uint BM_CLICK = 0x00F5;
        public const int BN_CLICKED = 0;
        public const int VK_RETURN = 0x0D;
        public const uint GA_ROOT = 2;
        public const uint GW_OWNER = 4;
        public const uint SYNCHRONIZE = 0x00100000;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint STILL_ACTIVE = 259;

        [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr hwnd, StringBuilder sb, int max);
        [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hwnd);
        [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr hwnd);
        [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
        [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr hwnd, uint cmd);
        [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hwnd);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern uint RegisterWindowMessage(string name);
        [DllImport("user32.dll", EntryPoint = "SendMessageTimeoutW")]
        public static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg, UIntPtr wParam, IntPtr lParam, uint flags, uint timeout, out UIntPtr result);
        [DllImport("user32.dll", EntryPoint = "SendMessageTimeoutW", CharSet = CharSet.Unicode)]
        public static extern IntPtr SendMessageTimeoutGetText(IntPtr hwnd, uint msg, UIntPtr wParam, StringBuilder lParam, uint flags, uint timeout, out UIntPtr result);
        [DllImport("user32.dll", EntryPoint = "SendMessageTimeoutW", CharSet = CharSet.Unicode)]
        public static extern IntPtr SendMessageTimeoutSetText(IntPtr hwnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
        [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr handle, uint ms);
        [DllImport("kernel32.dll")] public static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);

        [DllImport("oleacc.dll", PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        public static extern object ObjectFromLresult(UIntPtr lResult, [MarshalAs(UnmanagedType.LPStruct)] Guid refiid, IntPtr wParam);

        [DllImport("ole32.dll")] public static extern int CoRegisterMessageFilter(IOleMessageFilter newFilter, out IOleMessageFilter oldFilter);

        public static string ClassOf(IntPtr hwnd)
        {
            StringBuilder sb = new StringBuilder(256);
            GetClassName(hwnd, sb, sb.Capacity);
            return sb.ToString();
        }

        /// <summary>WM_GETTEXT (works for controls of another process, unlike GetWindowText).</summary>
        public static string TextOf(IntPtr hwnd)
        {
            UIntPtr len;
            if (SendMessageTimeout(hwnd, WM_GETTEXTLENGTH, UIntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, 1000, out len) == IntPtr.Zero) return "";
            int n = (int)len.ToUInt64();
            if (n <= 0) return "";
            StringBuilder sb = new StringBuilder(n + 2);
            UIntPtr copied;
            if (SendMessageTimeoutGetText(hwnd, WM_GETTEXT, new UIntPtr((uint)(n + 1)), sb, SMTO_ABORTIFHUNG, 1000, out copied) == IntPtr.Zero) return "";
            return sb.ToString();
        }

        public static List<IntPtr> TopLevelWindows(uint pid)
        {
            List<IntPtr> found = new List<IntPtr>();
            EnumWindowsProc cb = delegate(IntPtr h, IntPtr l)
            {
                uint owner;
                GetWindowThreadProcessId(h, out owner);
                if (owner == pid) found.Add(h);
                return true;
            };
            EnumWindows(cb, IntPtr.Zero);
            GC.KeepAlive(cb);
            return found;
        }

        /// <summary>All descendants (EnumChildWindows already recurses).</summary>
        public static List<IntPtr> Descendants(IntPtr parent)
        {
            List<IntPtr> found = new List<IntPtr>();
            EnumWindowsProc cb = delegate(IntPtr h, IntPtr l) { found.Add(h); return true; };
            EnumChildWindows(parent, cb, IntPtr.Zero);
            GC.KeepAlive(cb);
            return found;
        }
    }

    /// <summary>COM message filter: retry calls the busy browser thread rejects (SERVERCALL_RETRYLATER)
    /// instead of failing at once with RPC_E_CALL_REJECTED.</summary>
    [ComImport, Guid("00000016-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOleMessageFilter
    {
        [PreserveSig] int HandleInComingCall(int dwCallType, IntPtr hTaskCaller, int dwTickCount, IntPtr lpInterfaceInfo);
        [PreserveSig] int RetryRejectedCall(IntPtr hTaskCallee, int dwTickCount, int dwRejectType);
        [PreserveSig] int MessagePending(IntPtr hTaskCallee, int dwTickCount, int dwPendingType);
    }

    internal sealed class RetryFilter : IOleMessageFilter
    {
        public int HandleInComingCall(int dwCallType, IntPtr hTaskCaller, int dwTickCount, IntPtr lpInterfaceInfo) { return 0; }
        public int RetryRejectedCall(IntPtr hTaskCallee, int dwTickCount, int dwRejectType)
        {
            if (dwRejectType == 2 && dwTickCount < 15000) return 150;   // SERVERCALL_RETRYLATER: retry in 150 ms
            return -1;
        }
        public int MessagePending(IntPtr hTaskCallee, int dwTickCount, int dwPendingType) { return 2; }   // PENDINGMSG_WAITDEFPROCESS
    }

    /// <summary>IServiceProvider (used to reach a frame's document through its IWebBrowser2).</summary>
    [ComImport, Guid("6D5140C1-7436-11CE-8034-00AA006009FA"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IServiceProvider
    {
        [PreserveSig] int QueryService(ref Guid guidService, ref Guid riid, [MarshalAs(UnmanagedType.IUnknown)] out object ppv);
    }

    internal sealed class DriverException : Exception
    {
        public object Detail;
        public DriverException(string message) : base(message) { }
        public DriverException(string message, object detail) : base(message) { Detail = detail; }
    }

    /// <summary>Ordered JSON object.</summary>
    internal sealed class JObj
    {
        public readonly List<KeyValuePair<string, object>> Items = new List<KeyValuePair<string, object>>();
        public JObj Add(string key, object value) { Items.Add(new KeyValuePair<string, object>(key, value)); return this; }
    }

    internal static class Json
    {
        public static string Write(object value)
        {
            StringBuilder sb = new StringBuilder();
            Append(sb, value);
            return sb.ToString();
        }

        static void Append(StringBuilder sb, object v)
        {
            if (v == null || v is DBNull) { sb.Append("null"); return; }
            if (v is string) { Quote(sb, (string)v); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is IntPtr) { sb.Append(((IntPtr)v).ToInt64().ToString(CultureInfo.InvariantCulture)); return; }
            if (v is int || v is long || v is short || v is byte || v is uint || v is ulong || v is ushort || v is sbyte)
            {
                sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return;
            }
            if (v is double || v is float || v is decimal)
            {
                double d = Convert.ToDouble(v, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) sb.Append("null");
                else sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            JObj o = v as JObj;
            if (o != null)
            {
                sb.Append('{');
                for (int i = 0; i < o.Items.Count; i++)
                {
                    if (i > 0) sb.Append(", ");
                    Quote(sb, o.Items[i].Key);
                    sb.Append(": ");
                    Append(sb, o.Items[i].Value);
                }
                sb.Append('}');
                return;
            }
            IEnumerable e = v as IEnumerable;
            if (e != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object item in e)
                {
                    if (!first) sb.Append(", ");
                    first = false;
                    Append(sb, item);
                }
                sb.Append(']');
                return;
            }
            Quote(sb, Convert.ToString(v, CultureInfo.InvariantCulture));
        }

        /// <summary>JSON string literal, pure ASCII (everything outside 0x20..0x7E is \uXXXX).</summary>
        static void Quote(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s ?? "")
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20 || c > 0x7E) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }

    /// <summary>One HTML document found in the browser process.</summary>
    internal sealed class DocRef
    {
        public IntPtr Hwnd;          // the Internet Explorer_Server window
        public string Kind;          // tab | dialog | frame
        public string FramePath = "";
        public object Doc;           // IHTMLDocument2 (IDispatch)
        public string Url = "";
        public string Title = "";
        public string ReadyState = "";
        public bool Visible;
        public string Error;

        public JObj Info()
        {
            JObj o = new JObj();
            o.Add("hwnd", Hwnd.ToInt64()).Add("kind", Kind).Add("url", Url).Add("title", Title)
             .Add("readyState", ReadyState).Add("visible", Visible);
            if (FramePath.Length > 0) o.Add("frame", FramePath);
            if (Error != null) o.Add("error", Error);
            return o;
        }
    }

    internal static class Program
    {
        static readonly Guid IID_IHTMLDocument2 = new Guid("332C4425-26CB-11D0-B483-00C04FD90119");
        static readonly Guid IID_IWebBrowserApp = new Guid("0002DF05-0000-0000-C000-000000000046");
        static readonly Guid IID_IWebBrowser2 = new Guid("D30C1661-CDAF-11D0-8A3E-00C04FC9E26E");
        static uint wmHtmlGetObject;

        [STAThread]
        static int Main(string[] args)
        {
            object result;
            try
            {
                IOleMessageFilter old;
                Native.CoRegisterMessageFilter(new RetryFilter(), out old);
                wmHtmlGetObject = Native.RegisterWindowMessage("WM_HTML_GETOBJECT");
                result = Run(args);
            }
            catch (DriverException ex)
            {
                JObj err = new JObj().Add("error", ex.Message);
                if (ex.Detail != null) err.Add("detail", ex.Detail);
                Emit(err);
                return 1;
            }
            catch (Exception ex)
            {
                Exception inner = Unwrap(ex);
                JObj err = new JObj().Add("error", inner.GetType().Name + ": " + inner.Message);
                COMException com = inner as COMException;
                if (com != null) err.Add("hresult", "0x" + com.ErrorCode.ToString("x8", CultureInfo.InvariantCulture));
                Emit(err);
                return 1;
            }
            Emit(result);
            return 0;
        }

        static void Emit(object value)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(Json.Write(value) + "\n");
            using (Stream stdout = Console.OpenStandardOutput())
            {
                stdout.Write(bytes, 0, bytes.Length);
                stdout.Flush();
            }
        }

        // ------------------------------------------------------------------ argument handling

        sealed class Args
        {
            public string Command;
            public readonly Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.Ordinal);

            public string Get(string name) { string v; return Values.TryGetValue(name, out v) ? v : null; }
            public bool Has(string name) { return Values.ContainsKey(name); }

            public string Require(string name)
            {
                string v = Get(name);
                if (v == null) throw new DriverException(Command + ": --" + name + " is required");
                return v;
            }

            public double Seconds(string name, double fallback)
            {
                string v = Get(name);
                if (v == null) return fallback;
                double d;
                if (!double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out d) || d < 0)
                    throw new DriverException(Command + ": --" + name + " must be a number of seconds");
                return d;
            }

            public uint Pid()
            {
                uint pid;
                if (!uint.TryParse(Require("pid"), NumberStyles.Integer, CultureInfo.InvariantCulture, out pid) || pid == 0)
                    throw new DriverException(Command + ": --pid must be a process id");
                return pid;
            }
        }

        static readonly string[] KnownOptions = {
            "pid", "url", "text", "timeout", "id", "value", "fire", "link-text", "button-text", "name",
            "title", "button", "method", "to", "kind", "hwnd",
        };

        static Args Parse(string[] argv)
        {
            if (argv.Length == 0) throw new DriverException("usage: IEDriver <list|wait|value|select|click|text|attr|dialog|navigate|close> --pid P [options]");
            Args a = new Args();
            a.Command = argv[0];
            for (int i = 1; i < argv.Length; i++)
            {
                string k = argv[i];
                if (!k.StartsWith("--", StringComparison.Ordinal)) throw new DriverException("unexpected argument: " + k);
                string name = k.Substring(2);
                if (Array.IndexOf(KnownOptions, name) < 0) throw new DriverException("unknown option: " + k);
                if (i + 1 >= argv.Length) throw new DriverException("missing value for " + k);
                a.Values[name] = argv[++i];
            }
            return a;
        }

        static object Run(string[] argv)
        {
            Args a = Parse(argv);
            switch (a.Command)
            {
                case "list": return CmdList(a);
                case "wait": return CmdWait(a);
                case "value": return CmdValue(a);
                case "select": return CmdSelect(a);
                case "click": return CmdClick(a);
                case "text": return CmdText(a);
                case "attr": return CmdAttr(a);
                case "dialog": return CmdDialog(a);
                case "navigate": return CmdNavigate(a);
                case "close": return CmdClose(a);
                default: throw new DriverException("unknown command: " + a.Command);
            }
        }

        // ------------------------------------------------------------------ helpers

        static bool Contains(string haystack, string needle)
        {
            if (string.IsNullOrEmpty(needle)) return true;
            return haystack != null && haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>Collapses whitespace runs (innerText has \r\n and nbsp) so text matching is forgiving.</summary>
        static string Norm(string s)
        {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder(s.Length);
            bool space = false;
            foreach (char c in s)
            {
                if (char.IsWhiteSpace(c) || c == '\u00a0') { space = true; continue; }
                if (space && sb.Length > 0) sb.Append(' ');
                space = false;
                sb.Append(c);
            }
            return sb.ToString();
        }

        static string Short(string s, int max)
        {
            s = Norm(s);
            return s.Length <= max ? s : s.Substring(0, max - 1) + "\u2026";
        }

        static string Str(object v)
        {
            if (v == null || v is DBNull) return null;
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        /// <summary>Property read through IDispatch; null when the property does not exist or throws.</summary>
        static object Prop(object com, string name)
        {
            if (com == null) return null;
            try { return com.GetType().InvokeMember(name, BindingFlags.GetProperty, null, com, null, CultureInfo.InvariantCulture); }
            catch (Exception) { return null; }
        }

        static string PropStr(object com, string name) { return Str(Prop(com, name)) ?? ""; }

        // Late-bound IDispatch (Type.InvokeMember = GetIDsOfNames + Invoke).  Deliberately NOT C# 'dynamic':
        // its COM binder walks the MSHTML type library through cross-process ITypeInfo calls for every new
        // interface it meets, which cost 0.3 s and more per interface in every (short-lived) driver process.
        // Member names are case-sensitive (document.URL, not url).

        static object Get(object com, string name)
        {
            object v = com.GetType().InvokeMember(name, BindingFlags.GetProperty, null, com, null, CultureInfo.InvariantCulture);
            return v is DBNull ? null : v;
        }

        static void Set(object com, string name, object value)
        {
            com.GetType().InvokeMember(name, BindingFlags.SetProperty, null, com, new object[] { value }, CultureInfo.InvariantCulture);
        }

        static object Call(object com, string name, params object[] args)
        {
            object v = com.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, com, args, CultureInfo.InvariantCulture);
            return v is DBNull ? null : v;
        }

        static int Count(object collection)
        {
            return Convert.ToInt32(Get(collection, "length"), CultureInfo.InvariantCulture);
        }

        /// <summary>The COMException behind InvokeMember's TargetInvocationException wrapping.</summary>
        static Exception Unwrap(Exception ex)
        {
            while (ex is TargetInvocationException && ex.InnerException != null) ex = ex.InnerException;
            return ex;
        }

        static void Sleep(int ms) { Thread.Sleep(ms); }

        static double Now() { return Environment.TickCount / 1000.0; }

        // ------------------------------------------------------------------ documents

        static void EnsureProcess(uint pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) throw new DriverException("process " + pid + " is not running");
            uint code;
            bool ok = Native.GetExitCodeProcess(h, out code);
            Native.CloseHandle(h);
            if (ok && code != Native.STILL_ACTIVE) throw new DriverException("process " + pid + " has exited (code " + code + ")");
        }

        static object DocumentOf(IntPtr ieServer)
        {
            UIntPtr lres;
            IntPtr ok = Native.SendMessageTimeout(ieServer, wmHtmlGetObject, UIntPtr.Zero, IntPtr.Zero, Native.SMTO_ABORTIFHUNG, 2000, out lres);
            if (ok == IntPtr.Zero || lres == UIntPtr.Zero) return null;
            return Native.ObjectFromLresult(lres, IID_IHTMLDocument2, IntPtr.Zero);
        }

        static void Fill(DocRef d)
        {
            d.Url = PropStr(d.Doc, "URL");   // MSHTML's IDispatch names are case-sensitive ("url" is unknown)
            d.Title = PropStr(d.Doc, "title");
            d.ReadyState = PropStr(d.Doc, "readyState");
        }

        /// <summary>Every document of the process: tabs, dialogs, then (same-origin) frames of each.</summary>
        static List<DocRef> Collect(uint pid)
        {
            EnsureProcess(pid);
            List<DocRef> docs = new List<DocRef>();
            foreach (IntPtr top in Native.TopLevelWindows(pid))
            {
                string kind = Native.ClassOf(top) == "Internet Explorer_TridentDlgFrame" ? "dialog" : "tab";
                foreach (IntPtr child in Native.Descendants(top))
                {
                    if (Native.ClassOf(child) != "Internet Explorer_Server") continue;
                    DocRef d = new DocRef();
                    d.Hwnd = child;
                    d.Kind = kind;
                    d.Visible = Native.IsWindowVisible(child);
                    try { d.Doc = DocumentOf(child); }
                    catch (Exception ex) { d.Error = "WM_HTML_GETOBJECT: " + ex.Message; }
                    if (d.Doc == null && d.Error == null) d.Error = "WM_HTML_GETOBJECT: no document (window busy?)";
                    if (d.Doc != null) Fill(d);
                    docs.Add(d);
                    if (d.Doc != null) AddFrames(docs, d, d.Doc, "", 0);
                }
            }
            return docs;
        }

        static void AddFrames(List<DocRef> docs, DocRef parent, object doc, string path, int depth)
        {
            if (depth > 4) return;
            int n = 0;
            object frames = null;
            try { frames = Get(doc, "frames"); n = Count(frames); }
            catch (Exception) { return; }
            for (int i = 0; i < n; i++)
            {
                object fdoc = null;
                try { fdoc = FrameDocument(Call(frames, "item", i)); }
                catch (Exception) { fdoc = null; }
                string p = path.Length == 0 ? i.ToString(CultureInfo.InvariantCulture) : path + "/" + i.ToString(CultureInfo.InvariantCulture);
                DocRef d = new DocRef();
                d.Hwnd = parent.Hwnd;
                d.Kind = "frame";
                d.FramePath = p;
                d.Visible = parent.Visible;
                d.Doc = fdoc;
                if (fdoc == null) d.Error = "frame document not accessible";
                else Fill(d);
                docs.Add(d);
                if (fdoc != null) AddFrames(docs, d, fdoc, p, depth + 1);
            }
        }

        /// <summary>window.document, or (cross-origin frames) IServiceProvider -> IWebBrowser2.Document.</summary>
        static object FrameDocument(object window)
        {
            if (window == null) return null;
            try
            {
                object doc = Get(window, "document");
                if (doc != null) return doc;
            }
            catch (Exception) { }
            IServiceProvider sp = window as IServiceProvider;
            if (sp == null) return null;
            Guid service = IID_IWebBrowserApp, iid = IID_IWebBrowser2;
            object wb;
            if (sp.QueryService(ref service, ref iid, out wb) != 0 || wb == null) return null;
            return Get(wb, "Document");
        }

        /// <summary>--url / --kind / --hwnd filters.  Entries without a document (WM_HTML_GETOBJECT failed)
        /// only pass when <paramref name="allowBroken"/> (list shows them, with "error").</summary>
        static bool Matches(DocRef d, Args a, bool allowBroken = false)
        {
            if (d.Doc == null && !allowBroken) return false;
            if (!Contains(d.Url, a.Get("url") ?? "")) return false;
            string kind = a.Get("kind");
            if (!string.IsNullOrEmpty(kind) && !string.Equals(kind, d.Kind, StringComparison.OrdinalIgnoreCase)) return false;
            string hwnd = a.Get("hwnd");
            if (!string.IsNullOrEmpty(hwnd))
            {
                long h;
                if (!long.TryParse(hwnd, NumberStyles.Integer, CultureInfo.InvariantCulture, out h)) throw new DriverException("--hwnd must be a number");
                if (d.Hwnd.ToInt64() != h) return false;
            }
            return true;
        }

        static List<object> Infos(List<DocRef> docs)
        {
            List<object> list = new List<object>();
            foreach (DocRef d in docs) list.Add(d.Info());
            return list;
        }

        static string BodyText(object doc)
        {
            object body = Prop(doc, "body");
            if (body != null)
            {
                string t = PropStr(body, "innerText");
                if (t.Length > 0) return t;
            }
            return PropStr(Prop(doc, "documentElement"), "innerText");   // frameset documents have no text body
        }

        /// <summary>Polls until a matching document yields a non-null result from <paramref name="finder"/>.</summary>
        static KeyValuePair<DocRef, object> Resolve(uint pid, Args a, Func<DocRef, object> finder, string what, double defaultTimeout)
        {
            double deadline = Now() + a.Seconds("timeout", defaultTimeout);
            List<DocRef> docs;
            while (true)
            {
                docs = Collect(pid);
                // complete documents first: during a navigation the old and the new page can both match
                for (int pass = 0; pass < 2; pass++)
                {
                    foreach (DocRef d in docs)
                    {
                        if (!Matches(d, a)) continue;
                        bool complete = d.ReadyState == "complete";
                        if ((pass == 0) != complete) continue;
                        object found = null;
                        try { found = finder(d); } catch (Exception) { found = null; }
                        if (found != null) return new KeyValuePair<DocRef, object>(d, found);
                    }
                }
                if (Now() >= deadline) break;
                Sleep(200);
            }
            throw new DriverException(what + " not found in a document whose url contains '" + (a.Get("url") ?? "") + "'", Infos(docs));
        }

        static object ById(DocRef d, string id)
        {
            return Call(d.Doc, "getElementById", id);
        }

        static JObj Describe(object el)
        {
            JObj o = new JObj();
            o.Add("tag", PropStr(el, "tagName").ToLowerInvariant());
            o.Add("id", PropStr(el, "id"));
            string text = PropStr(el, "innerText");
            if (text.Length == 0) text = PropStr(el, "value");
            o.Add("text", Short(text, 80));
            return o;
        }

        // ------------------------------------------------------------------ commands

        static object CmdList(Args a)
        {
            uint pid = a.Pid();
            List<object> result = new List<object>();
            foreach (DocRef d in Collect(pid))
            {
                if (!Matches(d, a, true)) continue;
                result.Add(d.Info());
            }
            return result;
        }

        static object CmdWait(Args a)
        {
            uint pid = a.Pid();
            string text = a.Get("text");
            double deadline = Now() + a.Seconds("timeout", 30);
            List<DocRef> docs;
            while (true)
            {
                docs = Collect(pid);
                foreach (DocRef d in docs)
                {
                    if (!Matches(d, a) || d.ReadyState != "complete") continue;
                    if (text != null)
                    {
                        string body = "";
                        try { body = BodyText(d.Doc); } catch (Exception) { }
                        if (!Contains(Norm(body), Norm(text))) continue;
                    }
                    return d.Info();
                }
                if (Now() >= deadline) break;
                Sleep(250);
            }
            throw new DriverException("timeout waiting for a complete document whose url contains '" + (a.Get("url") ?? "") + "'"
                + (text != null ? " and text '" + text + "'" : ""), Infos(docs));
        }

        static object CmdValue(Args a)
        {
            uint pid = a.Pid();
            string id = a.Require("id");
            string value = a.Require("value");
            string fire = a.Get("fire");
            KeyValuePair<DocRef, object> t = Resolve(pid, a, delegate(DocRef d) { return ById(d, id); }, "element #" + id, 10);
            Set(t.Value, "value", value);
            JObj result = new JObj().Add("element", Describe(t.Value)).Add("value", PropStr(t.Value, "value"));
            if (!string.IsNullOrEmpty(fire)) result.Add("fired", FireEvent(t.Key, t.Value, fire));
            return result.Add("doc", t.Key.Info());
        }

        /// <summary>element.fireEvent("onX") (IE5-10 document modes); falls back to createEvent/dispatchEvent.</summary>
        static string FireEvent(DocRef d, object element, string name)
        {
            string on = name.StartsWith("on", StringComparison.OrdinalIgnoreCase) ? name : "on" + name;
            try { Call(element, "fireEvent", on); return "fireEvent"; }
            catch (Exception) { }
            try
            {
                object ev = Call(d.Doc, "createEvent", "HTMLEvents");
                Call(ev, "initEvent", on.Substring(2), true, false);
                Call(element, "dispatchEvent", ev);
                return "dispatchEvent";
            }
            catch (Exception ex) { throw new DriverException("could not fire " + on + ": " + Unwrap(ex).Message); }
        }

        static object CmdSelect(Args a)
        {
            uint pid = a.Pid();
            string id = a.Require("id");
            string text = a.Get("text");
            string value = a.Get("value");
            if ((text == null) == (value == null)) throw new DriverException("select: give exactly one of --text or --value");
            KeyValuePair<DocRef, object> t = Resolve(pid, a, delegate(DocRef d) { return ById(d, id); }, "element #" + id, 10);
            object options = Get(t.Value, "options");
            int n = Count(options);
            int index = -1;
            List<object> seen = new List<object>();
            for (int pass = 0; pass < 2 && index < 0; pass++)   // exact match first, then substring
            {
                for (int i = 0; i < n; i++)
                {
                    object opt = Call(options, "item", i);
                    string otext = Norm(PropStr(opt, "text"));
                    string ovalue = PropStr(opt, "value");
                    if (pass == 0) seen.Add(new JObj().Add("text", otext).Add("value", ovalue));
                    bool hit = text != null
                        ? (pass == 0 ? string.Equals(otext, Norm(text), StringComparison.Ordinal) : Contains(otext, Norm(text)))
                        : (pass == 0 && string.Equals(ovalue, value, StringComparison.Ordinal));
                    if (hit) { index = i; break; }
                }
            }
            if (index < 0) throw new DriverException("select #" + id + ": no option with " + (text != null ? "text '" + text + "'" : "value '" + value + "'"), seen);
            object chosen = Call(options, "item", index);
            Set(chosen, "selected", true);
            Set(t.Value, "selectedIndex", index);
            JObj result = new JObj().Add("element", Describe(t.Value)).Add("selectedIndex", index)
                .Add("text", Norm(PropStr(chosen, "text"))).Add("value", PropStr(chosen, "value"));
            result.Add("doc", t.Key.Info());   // before onchange: an autopostback replaces the document
            result.Add("fired", FireEvent(t.Key, t.Value, "onchange"));
            return result;
        }

        static object FindLink(DocRef d, string text)
        {
            object links = Call(d.Doc, "getElementsByTagName", "a");
            int n = Count(links);
            string want = Norm(text);
            for (int i = 0; i < n; i++)
            {
                object a = Call(links, "item", i);
                if (Contains(Norm(PropStr(a, "innerText")), want)) return a;
            }
            return null;
        }

        static object FindButton(DocRef d, string text)
        {
            string want = Norm(text);
            object inputs = Call(d.Doc, "getElementsByTagName", "input");
            int n = Count(inputs);
            for (int i = 0; i < n; i++)
            {
                object input = Call(inputs, "item", i);
                string type = PropStr(input, "type").ToLowerInvariant();
                if (type != "submit" && type != "button" && type != "reset" && type != "image") continue;
                if (Contains(Norm(PropStr(input, "value")), want) || (type == "image" && Contains(PropStr(input, "alt"), want))) return input;
            }
            object buttons = Call(d.Doc, "getElementsByTagName", "button");
            n = Count(buttons);
            for (int i = 0; i < n; i++)
            {
                object b = Call(buttons, "item", i);
                if (Contains(Norm(PropStr(b, "innerText")), want)) return b;
            }
            return null;
        }

        static object CmdClick(Args a)
        {
            uint pid = a.Pid();
            string id = a.Get("id");
            string linkText = a.Get("link-text");
            string buttonText = a.Get("button-text");
            int given = (id != null ? 1 : 0) + (linkText != null ? 1 : 0) + (buttonText != null ? 1 : 0);
            if (given != 1) throw new DriverException("click: give exactly one of --id, --link-text or --button-text");
            KeyValuePair<DocRef, object> t;
            if (id != null) t = Resolve(pid, a, delegate(DocRef d) { return ById(d, id); }, "element #" + id, 10);
            else if (linkText != null) t = Resolve(pid, a, delegate(DocRef d) { return FindLink(d, linkText); }, "link '" + linkText + "'", 10);
            else t = Resolve(pid, a, delegate(DocRef d) { return FindButton(d, buttonText); }, "button '" + buttonText + "'", 10);
            // describe BEFORE clicking: the click may navigate the document away
            JObj result = new JObj().Add("clicked", Describe(t.Value)).Add("doc", t.Key.Info());
            try { Call(t.Value, "click"); }
            catch (Exception ex)
            {
                // window.close() inside the handler (e.g. a dialog's 閉じる button) can tear the document
                // down before the call returns: the click itself happened.
                COMException com = Unwrap(ex) as COMException;
                if (com == null || !IsDisconnect(com.ErrorCode)) throw;
                result.Add("note", "document went away during the click (0x" + com.ErrorCode.ToString("x8", CultureInfo.InvariantCulture) + ")");
            }
            return result;
        }

        static bool IsDisconnect(int hr)
        {
            unchecked
            {
                return hr == (int)0x80010108    // RPC_E_DISCONNECTED
                    || hr == (int)0x800706BA    // RPC_S_SERVER_UNAVAILABLE
                    || hr == (int)0x800706BE    // RPC_S_CALL_FAILED
                    || hr == (int)0x80010012;   // RPC_E_SERVER_DIED_DNE
            }
        }

        static object CmdText(Args a)
        {
            uint pid = a.Pid();
            string id = a.Get("id");
            KeyValuePair<DocRef, object> t;
            if (id != null)
                t = Resolve(pid, a, delegate(DocRef d) { return ById(d, id); }, "element #" + id, 10);
            else
                t = Resolve(pid, a, delegate(DocRef d) { return d.Doc; }, "document", 10);
            string text = id != null ? PropStr(t.Value, "innerText") : BodyText(t.Key.Doc);
            return new JObj().Add("text", text).Add("doc", t.Key.Info());
        }

        static object CmdAttr(Args a)
        {
            uint pid = a.Pid();
            string id = a.Require("id");
            string name = a.Require("name");
            KeyValuePair<DocRef, object> t = Resolve(pid, a, delegate(DocRef d) { return ById(d, id); }, "element #" + id, 10);
            object value = null;
            string source = "property";
            bool found = false;
            try { value = Get(t.Value, name); found = true; }
            catch (Exception) { found = false; }
            if (!found || value == null)
            {
                try
                {
                    object attr = Call(t.Value, "getAttribute", name);
                    if (attr != null) { value = attr; source = "attribute"; found = true; }
                }
                catch (Exception) { }
            }
            if (value != null && !(value is string) && !(value is bool) && !value.GetType().IsPrimitive)
                value = Convert.ToString(value, CultureInfo.InvariantCulture);   // COM objects etc.
            return new JObj().Add("name", name).Add("value", value).Add("source", found ? source : "missing")
                .Add("element", Describe(t.Value)).Add("doc", t.Key.Info());
        }

        // ------------------------------------------------------------------ standard dialogs

        sealed class DialogInfo
        {
            public IntPtr Hwnd;
            public string Title;
            public List<KeyValuePair<IntPtr, string>> Buttons = new List<KeyValuePair<IntPtr, string>>();
            public List<string> Texts = new List<string>();

            public JObj Info()
            {
                List<object> buttons = new List<object>();
                foreach (KeyValuePair<IntPtr, string> b in Buttons) buttons.Add(b.Value);
                return new JObj().Add("hwnd", Hwnd.ToInt64()).Add("title", Title).Add("buttons", buttons).Add("texts", Texts);
            }
        }

        static List<DialogInfo> Dialogs(uint pid)
        {
            List<DialogInfo> result = new List<DialogInfo>();
            foreach (IntPtr top in Native.TopLevelWindows(pid))
            {
                if (Native.ClassOf(top) != "#32770" || !Native.IsWindowVisible(top)) continue;
                DialogInfo d = new DialogInfo();
                d.Hwnd = top;
                d.Title = Native.TextOf(top);
                foreach (IntPtr child in Native.Descendants(top))
                {
                    if (!Native.IsWindowVisible(child)) continue;
                    string cls = Native.ClassOf(child);
                    if (cls == "Button") d.Buttons.Add(new KeyValuePair<IntPtr, string>(child, Native.TextOf(child)));
                    else if (cls == "Static")
                    {
                        string t = Native.TextOf(child);
                        if (t.Trim().Length > 0) d.Texts.Add(t);
                    }
                }
                result.Add(d);
            }
            return result;
        }

        static string StripMnemonic(string s)
        {
            return (s ?? "").Replace("&&", "\u0001").Replace("&", "").Replace("\u0001", "&");
        }

        static object CmdDialog(Args a)
        {
            uint pid = a.Pid();
            string title = a.Get("title") ?? "";
            string text = a.Get("text");
            string button = a.Get("button");
            string method = a.Get("method") ?? "command";
            if (method != "command" && method != "bmclick") throw new DriverException("dialog: --method must be command or bmclick");
            double deadline = Now() + a.Seconds("timeout", 10);
            List<DialogInfo> seen;
            while (true)
            {
                EnsureProcess(pid);
                seen = Dialogs(pid);
                foreach (DialogInfo d in seen)
                {
                    if (!Contains(d.Title, title)) continue;
                    if (text != null)
                    {
                        bool any = false;
                        foreach (string s in d.Texts) if (Contains(Norm(s), Norm(text))) { any = true; break; }
                        if (!any) continue;
                    }
                    if (button == null) return d.Info();
                    foreach (KeyValuePair<IntPtr, string> b in d.Buttons)
                    {
                        if (!Contains(StripMnemonic(b.Value), button) || !Native.IsWindowEnabled(b.Key)) continue;
                        Press(d.Hwnd, b.Key, method);
                        bool closed = false;
                        double until = Now() + 5;
                        while (Now() < until)
                        {
                            if (!Native.IsWindow(d.Hwnd) || !Native.IsWindowVisible(d.Hwnd)) { closed = true; break; }
                            Sleep(100);
                        }
                        return d.Info().Add("clicked", b.Value).Add("method", method).Add("closed", closed);
                    }
                }
                if (Now() >= deadline) break;
                Sleep(200);
            }
            List<object> infos = new List<object>();
            foreach (DialogInfo d in seen) infos.Add(d.Info());
            throw new DriverException("no dialog with title '" + title + "'" + (text != null ? " and text '" + text + "'" : "")
                + (button != null ? " and an enabled button '" + button + "'" : "") + " in process " + pid, infos);
        }

        /// <summary>"command": WM_COMMAND/BN_CLICKED posted to the dialog (works when the dialog is not the
        /// active window); "bmclick": BM_CLICK posted to the button (can be ignored by an inactive dialog).</summary>
        static void Press(IntPtr dialog, IntPtr button, string method)
        {
            if (method == "bmclick")
            {
                Native.PostMessage(button, Native.BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                return;
            }
            int id = Native.GetDlgCtrlID(button) & 0xFFFF;
            IntPtr wParam = new IntPtr((Native.BN_CLICKED << 16) | id);
            Native.PostMessage(dialog, Native.WM_COMMAND, wParam, button);
        }

        // ------------------------------------------------------------------ main window

        static IntPtr MainWindow(uint pid)
        {
            foreach (IntPtr top in Native.TopLevelWindows(pid))
            {
                if (!Native.IsWindowVisible(top)) continue;
                if (Native.GetWindow(top, Native.GW_OWNER) != IntPtr.Zero) continue;
                if (!Native.ClassOf(top).StartsWith("WindowsForms10.Window", StringComparison.Ordinal)) continue;
                return top;
            }
            throw new DriverException("main window of process " + pid + " not found");
        }

        /// <summary>While alert() / showModalDialog / the download dialog is up, the main window is disabled:
        /// a user cannot use the address box or the X button then, so neither can the driver.</summary>
        static IntPtr EnabledMainWindow(uint pid, string command)
        {
            IntPtr main = MainWindow(pid);
            if (Native.IsWindowEnabled(main)) return main;
            List<object> open = new List<object>();
            foreach (IntPtr top in Native.TopLevelWindows(pid))
            {
                string cls = Native.ClassOf(top);
                if (Native.IsWindowVisible(top) && (cls == "#32770" || cls == "Internet Explorer_TridentDlgFrame"))
                    open.Add(new JObj().Add("hwnd", top.ToInt64()).Add("class", cls).Add("title", Native.TextOf(top)));
            }
            throw new DriverException(command + ": the main window is disabled by a modal dialog; close the dialog first", open);
        }

        static object CmdNavigate(Args a)
        {
            uint pid = a.Pid();
            string to = a.Require("to");
            EnsureProcess(pid);
            IntPtr main = EnabledMainWindow(pid, "navigate");
            IntPtr edit = IntPtr.Zero;
            foreach (IntPtr child in Native.Descendants(main))
            {
                if (Native.ClassOf(child).IndexOf(".EDIT.", StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (!Native.IsWindowVisible(child)) continue;
                edit = child;
                break;
            }
            if (edit == IntPtr.Zero) throw new DriverException("address box (WinForms EDIT) not found in the main window");
            UIntPtr r;
            Native.SendMessageTimeoutSetText(edit, Native.WM_SETTEXT, UIntPtr.Zero, to, Native.SMTO_ABORTIFHUNG, 2000, out r);
            string typed = Native.TextOf(edit);
            if (typed != to) throw new DriverException("address box did not take the text (got '" + typed + "')");
            // Enter is SENT right after the text (the TextBox raises KeyDown from its window procedure, where
            // RecBrowser navigates the selected tab): a posted key could be overtaken by the browser's own
            // address-box refresh after a page load, which would then reload the old address instead.
            if (Native.SendMessageTimeout(edit, Native.WM_KEYDOWN, new UIntPtr((uint)Native.VK_RETURN), new IntPtr(0x001C0001),
                    Native.SMTO_ABORTIFHUNG, 5000, out r) == IntPtr.Zero)
                throw new DriverException("navigate: the browser did not process the Enter key");
            Native.PostMessage(edit, Native.WM_KEYUP, new IntPtr(Native.VK_RETURN), new IntPtr(unchecked((int)0xC01C0001)));
            return new JObj().Add("hwnd", edit.ToInt64()).Add("to", to);
        }

        static object CmdClose(Args a)
        {
            uint pid = a.Pid();
            double timeout = a.Seconds("timeout", 15);
            IntPtr proc = Native.OpenProcess(Native.SYNCHRONIZE | Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (proc == IntPtr.Zero) throw new DriverException("process " + pid + " is not running");
            try
            {
                IntPtr main = EnabledMainWindow(pid, "close");
                if (!Native.PostMessage(main, Native.WM_CLOSE, IntPtr.Zero, IntPtr.Zero))
                    throw new DriverException("PostMessage(WM_CLOSE) failed");
                JObj result = new JObj().Add("hwnd", main.ToInt64()).Add("posted", true);
                if (timeout <= 0) return result;
                uint wait = Native.WaitForSingleObject(proc, (uint)Math.Min(timeout * 1000.0, uint.MaxValue - 1));
                if (wait != 0) return result.Add("exited", false).Add("exitCode", null);
                uint code;
                Native.GetExitCodeProcess(proc, out code);
                return result.Add("exited", true).Add("exitCode", (long)code);
            }
            finally { Native.CloseHandle(proc); }
        }
    }
}
