// RecBrowser.cs -- reqrec "recording browser" for legacy intranet sites (DESIGN.md: IE host mode).
//
// Hosts the Internet Explorer engine (WebBrowser control = Shell.Explorer.2 / MSHTML, the same Trident
// engine Edge's IE mode uses) in this small process and routes ONLY THIS PROCESS's HTTP through the
// local reqrec recorder (mitmproxy).  Nothing in Windows is changed: no Internet Options proxy, no
// registry value, no CA certificate (the recorder is started with a catch-all --ignore-hosts pattern,
// so HTTPS on every port is tunnelled untouched and only plain http:// is recorded).
//
// Proven facts this file relies on (do not "modernise" them away):
//   * The per-process proxy must be set with InternetSetOptionA(NULL, INTERNET_OPTION_PROXY) and an
//     INTERNET_PROXY_INFO holding ANSI strings, BEFORE the first WebBrowser control is created.  The
//     Unicode (W) variant does not work.  INTERNET_OPTION_PER_CONNECTION_OPTION with a NULL handle
//     writes the registry and is never used here.
//   * The proxy bypass list must stay EMPTY: "<local>" would exclude dotless intranet names such as
//     http://kanri/ from the recording.
//   * Popups (window.open, target=_blank, form target=_blank, showModelessDialog, showModalDialog)
//     are hosted as new tabs by answering DWebBrowserEvents2.NewWindow3 / NewWindow2 with the
//     ActiveXInstance of a fresh control, so window.opener, the window name, the session and POST
//     bodies survive and all of their HTTP goes through the proxy.
//   * window.close() never raises DWebBrowserEvents2.WindowClosing on this engine build (verified with a
//     catch-all event sink, with and without RegisterAsBrowser).  MSHTML instead sends OLECMDID_CLOSE to
//     the control's site (IOleCommandTarget), so the site implements that interface and closes the tab.
//
// Build (inbox .NET Framework 4.8, C# 5 compiler, no installation needed):
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -nologo -target:winexe -platform:x86
//       -out:RecBrowser.exe -r:System.Windows.Forms.dll -r:System.Drawing.dll RecBrowser.cs
// Always 32-bit (-platform:x86), also on 64-bit Windows: legacy intranet pages use in-process ActiveX
// controls that mostly exist only as 32-bit DLLs, which Edge's IE mode loads in a 32-bit process; a
// 64-bit host cannot load them.
// Run:
//   RecBrowser.exe --proxy 127.0.0.1:PORT [--bypass ""] [--url http://...] [--title "..."]
//                  [--log path] [--selftest] [--seconds N]
// Exit codes: 0 = window closed normally, 2 = usage error, 3 = --selftest guard timeout.
//
// The language level is C# 5 (no string interpolation, nameof, expression-bodied members or ?.).
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace Reqrec.IeHost
{
    /// <summary>Subset of DWebBrowserEvents2 (dispatch ids from exdisp.idl) that the host needs.</summary>
    [ComImport, Guid("34A715A0-6587-11D0-924A-0020AFC7AC4D"), InterfaceType(ComInterfaceType.InterfaceIsIDispatch), TypeLibType(TypeLibTypeFlags.FHidden)]
    public interface DWebBrowserEvents2
    {
        [DispId(251)] void NewWindow2([In, Out, MarshalAs(UnmanagedType.IDispatch)] ref object ppDisp, [In, Out] ref bool Cancel);
        [DispId(263)] void WindowClosing([In] bool IsChildWindow, [In, Out] ref bool Cancel);
        [DispId(270)] void FileDownload([In] bool ActiveDocument, [In, Out] ref bool Cancel);
        [DispId(273)] void NewWindow3([In, Out, MarshalAs(UnmanagedType.IDispatch)] ref object ppDisp, [In, Out] ref bool Cancel, [In] uint dwFlags, [In, MarshalAs(UnmanagedType.BStr)] string bstrUrlContext, [In, MarshalAs(UnmanagedType.BStr)] string bstrUrl);
    }

    /// <summary>IOleCommandTarget (docobj.h), implemented by the control's site so MSHTML can ask the
    /// host to close a window.  Group ids are passed as raw pointers because the standard group is NULL.</summary>
    [ComImport, Guid("B722BCCB-4E68-101B-A2BC-00AA00404770"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOleCommandTarget
    {
        [PreserveSig] int QueryStatus(IntPtr pguidCmdGroup, uint cCmds, IntPtr prgCmds, IntPtr pCmdText);
        [PreserveSig] int Exec(IntPtr pguidCmdGroup, uint nCmdID, uint nCmdexecopt, IntPtr pvaIn, IntPtr pvaOut);
    }

    /// <summary>Append-only diagnostics log ("HH:mm:ss.fff text", UTF-8 without BOM).  The process has
    /// no console (winexe), so this file is the only place diagnostics go.  Never throws.</summary>
    internal static class Log
    {
        static StreamWriter writer;
        static readonly object gate = new object();

        public static void Open(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(path));
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                writer = new StreamWriter(path, true, new UTF8Encoding(false));
                writer.AutoFlush = true;
            }
            catch (Exception) { writer = null; }
        }

        public static void Write(string text)
        {
            lock (gate)
            {
                if (writer == null) return;
                try { writer.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + text); }
                catch (Exception) { }
            }
        }

        public static void Close()
        {
            lock (gate)
            {
                if (writer == null) return;
                try { writer.Flush(); writer.Dispose(); } catch (Exception) { }
                writer = null;
            }
        }
    }

    /// <summary>WinINet / urlmon per-process options.  Every call here affects this process only.</summary>
    internal static class WinInet
    {
        const int INTERNET_OPTION_PROXY = 38;
        const int INTERNET_OPTION_END_BROWSER_SESSION = 42;
        const int INTERNET_OPTION_SUPPRESS_BEHAVIOR = 81;
        const int INTERNET_SUPPRESS_COOKIE_PERSIST = 3;
        const int INTERNET_OPEN_TYPE_PROXY = 3;

        // DWORD + two pointers; Sequential + IntPtr gives the right layout for -platform:x86 (the
        // production build, see the header) and would for x64 as well.
        [StructLayout(LayoutKind.Sequential)]
        struct INTERNET_PROXY_INFO
        {
            public int dwAccessType;
            public IntPtr lpszProxy;
            public IntPtr lpszProxyBypass;
        }

        [DllImport("wininet.dll", SetLastError = true, EntryPoint = "InternetSetOptionA")]
        static extern bool InternetSetOptionA(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        [DllImport("urlmon.dll")]
        static extern int UrlMkSetSessionOption(int dwOption, IntPtr pBuffer, int dwBufferLength, int dwReserved);

        // Kept alive for the lifetime of the process: WinINet may keep pointing at these strings.
        static IntPtr proxyInfoBuffer = IntPtr.Zero;

        static IntPtr BuildProxyInfo(string server, string bypass, out int size)
        {
            INTERNET_PROXY_INFO info = new INTERNET_PROXY_INFO();
            info.dwAccessType = INTERNET_OPEN_TYPE_PROXY;
            info.lpszProxy = Marshal.StringToHGlobalAnsi(server);            // ANSI: the W variant breaks WinINet
            info.lpszProxyBypass = Marshal.StringToHGlobalAnsi(bypass ?? "");
            size = Marshal.SizeOf(typeof(INTERNET_PROXY_INFO));
            IntPtr buf = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(info, buf, false);
            return buf;
        }

        /// <summary>InternetSetOptionA(NULL, INTERNET_OPTION_PROXY): proxy for every WinINet handle of this
        /// process that uses the pre-configured settings (which is what MSHTML / urlmon do).</summary>
        public static bool SetProcessProxy(string server, string bypass, out int lastError)
        {
            int size;
            proxyInfoBuffer = BuildProxyInfo(server, bypass, out size);
            bool ok = InternetSetOptionA(IntPtr.Zero, INTERNET_OPTION_PROXY, proxyInfoBuffer, size);
            lastError = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }

        /// <summary>Belt and braces: the same proxy on urlmon's own session (UrlMkSetSessionOption).</summary>
        public static int SetUrlmonProxy(string server, string bypass)
        {
            int size;
            IntPtr buf = BuildProxyInfo(server, bypass, out size);
            try { return UrlMkSetSessionOption(INTERNET_OPTION_PROXY, buf, size, 0); }
            catch (Exception) { return -1; }
        }

        /// <summary>Do not persist cookies received by this process (the recording starts from a clean
        /// session every time, so the login itself gets recorded).</summary>
        public static bool SuppressCookiePersist(out int lastError)
        {
            IntPtr buf = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(buf, INTERNET_SUPPRESS_COOKIE_PERSIST);
            bool ok = InternetSetOptionA(IntPtr.Zero, INTERNET_OPTION_SUPPRESS_BEHAVIOR, buf, 4);
            lastError = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }

        /// <summary>Flush session cookies / cached credentials of the browser session.</summary>
        public static bool EndBrowserSession(out int lastError)
        {
            bool ok = InternetSetOptionA(IntPtr.Zero, INTERNET_OPTION_END_BROWSER_SESSION, IntPtr.Zero, 0);
            lastError = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }
    }

    /// <summary>WebBrowser with the DWebBrowserEvents2 events the stock control does not expose:
    /// NewWindow2/NewWindow3 (popups hosted by a control we supply), WindowClosing and FileDownload.</summary>
    public class ExtWebBrowser : WebBrowser
    {
        /// <summary>Short name used in the log ("tab1", "tab2", ...).</summary>
        public string Name2 = "";
        /// <summary>Returns the (already created) control that will host a popup; null cancels the popup.</summary>
        public Func<ExtWebBrowser, string, uint, ExtWebBrowser> NewWindowFactory;
        /// <summary>window.close() was called on this tab's document.</summary>
        public Action<ExtWebBrowser> CloseRequested;
        /// <summary>A real file download (FileDownload with ActiveDocument == false) started.</summary>
        public Action<ExtWebBrowser> DownloadDetected;

        AxHost.ConnectionPointCookie cookie;
        Sink sink;

        protected override void CreateSink()
        {
            base.CreateSink();
            try
            {
                sink = new Sink(this);
                cookie = new AxHost.ConnectionPointCookie(ActiveXInstance, sink, typeof(DWebBrowserEvents2));
            }
            catch (Exception ex) { Log.Write("event sink FAILED for " + Name2 + ": " + ex.Message); }
        }

        protected override void DetachSink()
        {
            if (cookie != null)
            {
                try { cookie.Disconnect(); } catch (Exception) { }
                cookie = null;
            }
            base.DetachSink();
        }

        protected override WebBrowserSiteBase CreateWebBrowserSiteBase()
        {
            return new CommandSite(this);
        }

        /// <summary>The control's site with an IOleCommandTarget.  When script calls window.close() MSHTML
        /// sends OLECMDID_CLOSE (standard group) to the site, for script-opened popups directly and for the
        /// top-level page after IE's own "close this window?" confirmation.  (DWebBrowserEvents2.WindowClosing
        /// is never raised by this engine build, so the command is the reliable signal.)  Every other command
        /// is declined so the control keeps its default behaviour.</summary>
        protected class CommandSite : WebBrowserSite, IOleCommandTarget
        {
            const int S_OK = 0;
            const int OLECMDERR_E_NOTSUPPORTED = unchecked((int)0x80040100);
            const int OLECMDERR_E_UNKNOWNGROUP = unchecked((int)0x80040104);
            const uint OLECMDID_CLOSE = 45;
            const uint OLECMDID_SHOWSCRIPTERROR = 40;
            static readonly Guid CGID_DocHostCommandHandler = new Guid("F38BC242-B950-11D1-8918-00C04FC2C836");

            readonly ExtWebBrowser owner;
            public CommandSite(ExtWebBrowser host) : base(host) { owner = host; }

            public int QueryStatus(IntPtr pguidCmdGroup, uint cCmds, IntPtr prgCmds, IntPtr pCmdText)
            {
                return pguidCmdGroup == IntPtr.Zero ? OLECMDERR_E_NOTSUPPORTED : OLECMDERR_E_UNKNOWNGROUP;
            }

            public int Exec(IntPtr pguidCmdGroup, uint nCmdID, uint nCmdexecopt, IntPtr pvaIn, IntPtr pvaOut)
            {
                if (pguidCmdGroup != IntPtr.Zero)
                {
                    Guid group;
                    try { group = (Guid)Marshal.PtrToStructure(pguidCmdGroup, typeof(Guid)); }
                    catch (Exception) { return OLECMDERR_E_UNKNOWNGROUP; }
                    if (group == CGID_DocHostCommandHandler && nCmdID == OLECMDID_SHOWSCRIPTERROR)
                    {
                        // A script error on a legacy page: no dialog, keep running the page's scripts
                        // (pvaOut = TRUE).  Only this prompt is suppressed; login / security prompts still show.
                        try { if (pvaOut != IntPtr.Zero) Marshal.GetNativeVariantForObject(true, pvaOut); }
                        catch (Exception) { }
                        Log.Write("script error suppressed in " + owner.Name2);
                        return S_OK;
                    }
                    return group == CGID_DocHostCommandHandler ? OLECMDERR_E_NOTSUPPORTED : OLECMDERR_E_UNKNOWNGROUP;
                }
                if (nCmdID == OLECMDID_CLOSE)
                {
                    Log.Write("OLECMDID_CLOSE " + owner.Name2 + " (window.close)");
                    try { if (owner.CloseRequested != null) owner.CloseRequested(owner); }
                    catch (Exception ex) { Log.Write("close request failed: " + ex.Message); }
                    return S_OK;
                }
                return pguidCmdGroup == IntPtr.Zero ? OLECMDERR_E_NOTSUPPORTED : OLECMDERR_E_UNKNOWNGROUP;
            }
        }

        class Sink : DWebBrowserEvents2
        {
            readonly ExtWebBrowser owner;
            public Sink(ExtWebBrowser o) { owner = o; }

            public void NewWindow2(ref object ppDisp, ref bool Cancel)
            {
                Log.Write("NewWindow2 from " + owner.Name2);
                Host(ref ppDisp, ref Cancel, 0, "");
            }

            public void NewWindow3(ref object ppDisp, ref bool Cancel, uint dwFlags, string bstrUrlContext, string bstrUrl)
            {
                Log.Write("NewWindow3 from " + owner.Name2 + " flags=0x" + dwFlags.ToString("x") + " url=" + bstrUrl);
                Host(ref ppDisp, ref Cancel, dwFlags, bstrUrl);
            }

            void Host(ref object ppDisp, ref bool Cancel, uint flags, string url)
            {
                ExtWebBrowser target = null;
                try { if (owner.NewWindowFactory != null) target = owner.NewWindowFactory(owner, url, flags); }
                catch (Exception ex) { Log.Write("  -> new tab FAILED: " + ex.Message); }
                if (target == null) { Cancel = true; Log.Write("  -> cancelled (no tab)"); return; }
                object ax = target.ActiveXInstance;
                if (ax == null) { Cancel = true; Log.Write("  -> cancelled (ActiveXInstance null)"); return; }
                ppDisp = ax;   // the engine navigates THIS control itself (keeps opener / name / POST body)
                Log.Write("  -> hosted in " + target.Name2);
            }

            public void WindowClosing(bool IsChildWindow, ref bool Cancel)
            {
                Log.Write("WindowClosing " + owner.Name2 + " child=" + IsChildWindow);
                if (owner.CloseRequested != null) owner.CloseRequested(owner);
            }

            public void FileDownload(bool ActiveDocument, ref bool Cancel)
            {
                // ActiveDocument == true fires for every ordinary page; false is a real file download.
                if (ActiveDocument) return;
                Log.Write("FileDownload " + owner.Name2 + " (file download)");
                if (owner.DownloadDetected != null) owner.DownloadDetected(owner);
            }
        }
    }

    /// <summary>Parsed command line.</summary>
    public class Options
    {
        public string Proxy;
        public string Bypass = "";
        public string Url = "about:blank";
        public string Title = "reqrec 記録用ブラウザ";
        public string LogPath;
        public bool SelfTest;
        public bool HttpsRecorded;
        public int Seconds = 20;

        public static Options Parse(string[] args)
        {
            Options o = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                bool hasValue = i + 1 < args.Length;
                switch (a)
                {
                    case "--proxy": if (hasValue) o.Proxy = args[++i]; break;
                    case "--bypass": if (hasValue) o.Bypass = args[++i] ?? ""; break;
                    case "--url": if (hasValue) o.Url = args[++i]; break;
                    case "--title": if (hasValue) o.Title = args[++i]; break;
                    case "--log": if (hasValue) o.LogPath = args[++i]; break;
                    case "--selftest": o.SelfTest = true; break;
                    case "--https": o.HttpsRecorded = true; break;
                    case "--seconds":
                        if (hasValue)
                        {
                            int n;
                            if (int.TryParse(args[++i], out n) && n > 0) o.Seconds = n;
                        }
                        break;
                    default: break;   // unknown arguments are ignored
                }
            }
            if (string.IsNullOrEmpty(o.Url)) o.Url = "about:blank";
            if (string.IsNullOrEmpty(o.Title)) o.Title = "reqrec 記録用ブラウザ";
            return o;
        }
    }

    public class MainForm : Form
    {
        const int MaxTabText = 40;

        readonly Options opt;
        readonly TabControl tabs = new TabControl();
        readonly TextBox addressBox = new TextBox();
        readonly Button backButton = new Button();
        readonly Button forwardButton = new Button();
        readonly Button reloadButton = new Button();
        readonly Button closeTabButton = new Button();
        readonly Button stopButton = new Button();
        readonly ToolStripStatusLabel eventLabel = new ToolStripStatusLabel();
        int tabCounter = 0;
        bool selfTestStarted = false;

        public MainForm(Options options)
        {
            opt = options;
            Text = opt.Title + " — 記録中";
            Font baseFont = SystemFonts.MessageBoxFont ?? SystemFonts.DefaultFont;
            Font = new Font(baseFont.FontFamily, Math.Max(baseFont.Size, 10F));
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = true;
            MinimumSize = new Size(640, 400);
            Rectangle area = Screen.PrimaryScreen.WorkingArea;
            Size = new Size(Math.Min(1100, area.Width - 20), Math.Min(800, area.Height - 20));

            BuildToolbar();
            BuildStatusStrip();

            tabs.Dock = DockStyle.Fill;
            tabs.Padding = new Point(14, 5);
            tabs.SelectedIndexChanged += delegate { UpdateToolbar(); };
            Controls.Add(tabs);
            tabs.BringToFront();

            ExtWebBrowser first = NewTab(false);
            if (opt.SelfTest)
            {
                first.DocumentCompleted += FirstPageCompletedForSelfTest;
                Timer guard = new Timer();
                guard.Interval = opt.Seconds * 1000;
                guard.Tick += delegate
                {
                    guard.Stop();
                    Log.Write("selftest: guard timeout after " + opt.Seconds + " s -> exit 3");
                    Program.ExitCode = 3;
                    Close();
                };
                guard.Start();
            }
            NavigateTab(first, opt.Url);
            UpdateToolbar();
            FormClosed += delegate { Log.Write("window closed -> exit " + Program.ExitCode); };
        }

        // ------------------------------------------------------------------ UI construction

        void BuildToolbar()
        {
            TableLayoutPanel bar = new TableLayoutPanel();
            bar.Dock = DockStyle.Top;
            bar.AutoSize = true;
            bar.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            bar.ColumnCount = 6;
            bar.RowCount = 1;
            bar.Padding = new Padding(6, 4, 6, 4);
            bar.BackColor = SystemColors.Control;
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            SetupToolButton(backButton, "← 戻る");
            SetupToolButton(forwardButton, "→ 進む");
            SetupToolButton(reloadButton, "⟳ 更新");
            SetupToolButton(closeTabButton, "⨯ タブを閉じる");
            backButton.Click += delegate { ExtWebBrowser b = Active; if (b != null && b.CanGoBack) Safe(delegate { b.GoBack(); }); };
            forwardButton.Click += delegate { ExtWebBrowser b = Active; if (b != null && b.CanGoForward) Safe(delegate { b.GoForward(); }); };
            reloadButton.Click += delegate { ExtWebBrowser b = Active; if (b != null) Safe(delegate { b.Refresh(WebBrowserRefreshOption.Normal); }); };
            closeTabButton.Click += delegate { if (tabs.SelectedTab != null) CloseTab(tabs.SelectedTab); };

            addressBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            addressBox.Margin = new Padding(6, 3, 6, 3);
            addressBox.KeyDown += AddressKeyDown;

            stopButton.Text = "■ 記録をおわる";
            stopButton.AutoSize = true;
            stopButton.Padding = new Padding(16, 5, 16, 5);
            stopButton.Margin = new Padding(8, 2, 2, 2);
            stopButton.FlatStyle = FlatStyle.Flat;
            stopButton.FlatAppearance.BorderSize = 0;
            stopButton.BackColor = Color.FromArgb(196, 30, 30);
            stopButton.ForeColor = Color.White;
            stopButton.UseVisualStyleBackColor = false;
            stopButton.Font = new Font(Font.FontFamily, Font.Size + 2F, FontStyle.Bold);
            stopButton.Click += delegate { Log.Write("stop button"); Program.ExitCode = 0; Close(); };

            bar.Controls.Add(backButton, 0, 0);
            bar.Controls.Add(forwardButton, 1, 0);
            bar.Controls.Add(reloadButton, 2, 0);
            bar.Controls.Add(addressBox, 3, 0);
            bar.Controls.Add(closeTabButton, 4, 0);
            bar.Controls.Add(stopButton, 5, 0);
            Controls.Add(bar);
        }

        void SetupToolButton(Button b, string text)
        {
            b.Text = text;
            b.AutoSize = true;
            b.Padding = new Padding(8, 4, 8, 4);
            b.Margin = new Padding(2);
            b.UseVisualStyleBackColor = true;
        }

        void BuildStatusStrip()
        {
            StatusStrip strip = new StatusStrip();
            strip.SizingGrip = false;
            ToolStripStatusLabel recording = new ToolStripStatusLabel(opt.HttpsRecorded
                ? "● 記録中 — このウィンドウで行った操作の通信を記録しています"
                : "● 記録中 — このウィンドウで開いた http:// のページの通信を記録しています（https:// は記録されません）");
            recording.Spring = true;
            recording.TextAlign = ContentAlignment.MiddleLeft;
            recording.ForeColor = Color.FromArgb(170, 0, 0);
            eventLabel.TextAlign = ContentAlignment.MiddleRight;
            strip.Items.Add(recording);
            strip.Items.Add(eventLabel);
            Controls.Add(strip);
        }

        // ------------------------------------------------------------------ tabs

        ExtWebBrowser Active
        {
            get
            {
                TabPage page = tabs.SelectedTab;
                if (page == null || page.Controls.Count == 0) return null;
                return page.Controls[0] as ExtWebBrowser;
            }
        }

        /// <summary>Creates a tab with a fresh control (handle forced so ActiveXInstance exists) and selects it.</summary>
        ExtWebBrowser NewTab(bool isPopup)
        {
            tabCounter++;
            string name = "tab" + tabCounter;
            TabPage page = new TabPage("新しいタブ");
            ExtWebBrowser wb = new ExtWebBrowser();
            wb.Name2 = name;
            wb.Dock = DockStyle.Fill;
            // Not Silent (= ScriptErrorsSuppressed): that would also hide the 「Windows セキュリティ」 login
            // prompt of Basic / Windows authentication.  Script errors are suppressed in CommandSite.Exec.
            wb.ScriptErrorsSuppressed = false;
            wb.IsWebBrowserContextMenuEnabled = true;
            wb.NewWindowFactory = delegate(ExtWebBrowser source, string url, uint flags) { return NewTab(true); };
            wb.CloseRequested = delegate(ExtWebBrowser b)
            {
                // Deferred: the engine is still inside window.close() (OLECMDID_CLOSE / WindowClosing)
                // when this runs, so the control must not be disposed synchronously.
                BeginInvoke(new Action(delegate { CloseTab(page); }));
            };
            wb.DownloadDetected = delegate(ExtWebBrowser b)
            {
                SetStatus(IsUnrecordedHttps(b.Url) ? "このダウンロード (https://) は記録されません" : "ダウンロードを記録しました");
            };
            bool titleAnnounced = !isPopup;
            wb.DocumentTitleChanged += delegate
            {
                string title = "";
                try { title = wb.DocumentTitle ?? ""; } catch (Exception) { }
                page.Text = TabText(title, wb);
                if (!titleAnnounced && title.Trim().Length > 0)
                {
                    titleAnnounced = true;
                    SetStatus("新しいタブ: " + Shorten(title.Trim(), MaxTabText));
                }
            };
            wb.Navigated += delegate(object s, WebBrowserNavigatedEventArgs e)
            {
                Log.Write("Navigated " + name + " -> " + e.Url);
                if (IsUnrecordedHttps(e.Url)) SetStatus("このページ (https://) は記録されません。http:// のページで操作してください");
                if (tabs.SelectedTab == page) UpdateToolbar();
            };
            wb.DocumentCompleted += delegate { if (tabs.SelectedTab == page) UpdateToolbar(); };
            wb.CanGoBackChanged += delegate { if (tabs.SelectedTab == page) UpdateToolbar(); };
            wb.CanGoForwardChanged += delegate { if (tabs.SelectedTab == page) UpdateToolbar(); };
            page.Controls.Add(wb);
            tabs.TabPages.Add(page);
            tabs.SelectedTab = page;
            IntPtr h = wb.Handle;   // force creation: ActiveXInstance must exist before the engine gets it
            if (isPopup) SetStatus("新しいタブを開きました");
            Log.Write("new tab " + name + (isPopup ? " (popup)" : "") + " handle=0x" + h.ToInt64().ToString("x"));
            return wb;
        }

        void CloseTab(TabPage page)
        {
            if (page == null || !tabs.TabPages.Contains(page)) return;
            ExtWebBrowser wb = page.Controls.Count > 0 ? page.Controls[0] as ExtWebBrowser : null;
            Log.Write("close tab " + (wb != null ? wb.Name2 : "?"));
            tabs.TabPages.Remove(page);
            try { if (wb != null) wb.Dispose(); } catch (Exception ex) { Log.Write("dispose failed: " + ex.Message); }
            try { page.Dispose(); } catch (Exception) { }
            if (tabs.TabPages.Count == 0)
            {
                ExtWebBrowser fresh = NewTab(false);   // never leave the window without a tab
                NavigateTab(fresh, "about:blank");
            }
            UpdateToolbar();
        }

        static string TabText(string title, ExtWebBrowser wb)
        {
            string t = (title ?? "").Trim();
            if (t.Length == 0)
            {
                try { if (wb.Url != null && wb.Url.ToString() != "about:blank") t = wb.Url.Host; } catch (Exception) { }
            }
            if (t.Length == 0) t = "新しいタブ";
            return Shorten(t, MaxTabText);
        }

        static string Shorten(string s, int max)
        {
            if (s.Length <= max) return s;
            return s.Substring(0, max - 1) + "…";
        }

        // ------------------------------------------------------------------ navigation / toolbar

        void NavigateTab(ExtWebBrowser wb, string url)
        {
            string target = (url ?? "").Trim();
            if (target.Length == 0) return;
            if (target.IndexOf("://", StringComparison.Ordinal) < 0 && !target.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
                target = "http://" + target;
            try { wb.Navigate(target); }
            catch (Exception ex) { Log.Write("navigate failed: " + ex.Message); SetStatus("このアドレスは開けません"); }
        }

        void AddressKeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;
            e.Handled = true;
            ExtWebBrowser b = Active;
            if (b != null) NavigateTab(b, addressBox.Text);
        }

        void UpdateToolbar()
        {
            ExtWebBrowser b = Active;
            string url = "";
            bool back = false, forward = false;
            if (b != null)
            {
                try { if (b.Url != null) url = b.Url.ToString(); } catch (Exception) { }
                try { back = b.CanGoBack; forward = b.CanGoForward; } catch (Exception) { }
            }
            if (url == "about:blank") url = "";
            if (!addressBox.Focused || addressBox.Text.Length == 0) addressBox.Text = url;
            backButton.Enabled = back;
            forwardButton.Enabled = forward;
        }

        bool IsUnrecordedHttps(Uri url)
        {
            return !opt.HttpsRecorded && url != null && url.Scheme == Uri.UriSchemeHttps;
        }

        void SetStatus(string text)
        {
            eventLabel.Text = text;
            Log.Write("status: " + text);
        }

        static void Safe(Action a)
        {
            try { a(); } catch (Exception ex) { Log.Write("action failed: " + ex.Message); }
        }

        // ------------------------------------------------------------------ --selftest

        void FirstPageCompletedForSelfTest(object sender, WebBrowserDocumentCompletedEventArgs e)
        {
            if (selfTestStarted) return;
            if (e.Url != null && e.Url.ToString() == "about:blank") return;
            selfTestStarted = true;
            ExtWebBrowser main = (ExtWebBrowser)sender;
            Log.Write("selftest: first page completed " + e.Url);
            Queue<Action> steps = new Queue<Action>();
            // doClosePopup (optional) opens a popup that closes itself: exercises the OLECMDID_CLOSE path.
            string[] functions = { "doOpen", "doBlankPost", "doBlankLink", "doModeless", "doModal", "doClosePopup" };
            foreach (string fn in functions)
            {
                string name = fn;
                steps.Enqueue(delegate
                {
                    if (SafeEval(main, "typeof " + name) != "function") { Log.Write("selftest: " + name + " not present, skipped"); return; }
                    object r = null;
                    try { r = main.Document.InvokeScript(name); }
                    catch (Exception ex) { Log.Write("selftest: " + name + " error: " + ex.Message); return; }
                    Log.Write("selftest: " + name + " -> " + (r == null ? "(null)" : r.ToString()));
                });
            }
            steps.Enqueue(delegate
            {
                Log.Write("selftest: tabs=" + tabs.TabPages.Count);
                foreach (TabPage p in tabs.TabPages)
                {
                    ExtWebBrowser b = p.Controls.Count > 0 ? p.Controls[0] as ExtWebBrowser : null;
                    if (b == null) continue;
                    string url = "(none)";
                    try { if (b.Url != null) url = b.Url.ToString(); } catch (Exception) { }
                    Log.Write("tab: " + url + " mode=" + SafeEval(b, "document.documentMode") + " opener=" + SafeEval(b, "window.opener ? 'yes' : 'no'") + " name=" + SafeEval(b, "window.name"));
                }
            });
            steps.Enqueue(delegate { Log.Write("selftest: done -> exit 0"); Program.ExitCode = 0; Close(); });

            Timer timer = new Timer();
            timer.Interval = 1500;
            timer.Tick += delegate
            {
                if (steps.Count == 0) { timer.Stop(); return; }
                try { steps.Dequeue()(); }
                catch (Exception ex) { Log.Write("selftest: step error: " + ex.Message); }
            };
            timer.Start();
        }

        static string SafeEval(ExtWebBrowser b, string expression)
        {
            try
            {
                if (b.Document == null) return "(no document)";
                object r = b.Document.InvokeScript("eval", new object[] { expression });
                return r == null ? "" : r.ToString();
            }
            catch (Exception ex) { return "(error " + ex.Message + ")"; }
        }
    }

    internal static class Program
    {
        public static int ExitCode = 0;

        [STAThread]
        static int Main(string[] args)
        {
            Options opt = Options.Parse(args);
            Log.Open(opt.LogPath);
            Log.Write("RecBrowser start");
            if (string.IsNullOrEmpty(opt.Proxy))
            {
                Log.Write("proxy (none) -> FAILED: --proxy 127.0.0.1:PORT is required");
                Log.Close();
                return 2;
            }

            // All WinINet options are set before the first WebBrowser control exists.  None of them
            // touches the registry or Internet Options; failures are logged and never fatal.
            int err;
            bool ok = WinInet.EndBrowserSession(out err);
            Log.Write("end browser session -> " + (ok ? "ok" : "FAILED (error " + err + ")"));
            ok = WinInet.SuppressCookiePersist(out err);
            Log.Write("suppress cookie persist -> " + (ok ? "ok" : "FAILED (error " + err + ")"));
            ok = WinInet.SetProcessProxy(opt.Proxy, opt.Bypass, out err);
            Log.Write("proxy " + opt.Proxy + " -> " + (ok ? "ok" : "FAILED (error " + err + ")"));
            if (!ok)
            {
                // Without the per-process proxy the window would say 「記録中」 while recording nothing.
                Log.Write("exit 4 (proxy could not be set)");
                Log.Close();
                MessageBox.Show(
                    "記録用の中継設定に失敗したため、記録できません (エラー " + err + ")。\n" +
                    "reqrec の画面でもう一度 [記録をはじめる] を押してください。直らない場合は管理者に連絡してください。",
                    "reqrec 記録用ブラウザ", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 4;
            }
            Log.Write("proxy bypass=\"" + opt.Bypass + "\"");
            int hr = WinInet.SetUrlmonProxy(opt.Proxy, opt.Bypass);
            Log.Write("urlmon proxy -> hr=0x" + hr.ToString("x"));

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e)
            {
                Log.Write("unhandled: " + e.Exception);
            };
            try
            {
                MainForm form = new MainForm(opt);
                Log.Write("title " + form.Text);
                Application.Run(form);
            }
            catch (Exception ex)
            {
                Log.Write("fatal: " + ex);
                Log.Close();
                return 1;
            }
            Log.Write("exit " + ExitCode);
            Log.Close();
            return ExitCode;
        }
    }
}
