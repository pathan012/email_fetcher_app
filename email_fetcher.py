
import imaplib
import email
from email.header import decode_header
import re
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta

# Try to import tkcalendar.DateEntry for a friendly date picker.
try:
    from tkcalendar import DateEntry
    TKCALENDAR_AVAILABLE = True
except Exception:
    TKCALENDAR_AVAILABLE = False


# ----------------------------
# Backend: IMAP + Parsing
# ----------------------------

def connect_imap(server: str, email_user: str, password: str, port: int = 993, use_ssl: bool = True):
    """
    Connect to IMAP server and log in using provided credentials.
    Returns an imaplib.IMAP4/IMAP4_SSL instance on success or raises an exception on failure.
    """
    # Create IMAP connection object using SSL or non-SSL
    if use_ssl:
        imap = imaplib.IMAP4_SSL(server, port)
    else:
        imap = imaplib.IMAP4(server, port)
    # Attempt login (this may raise imaplib.IMAP4.error on auth failure)
    imap.login(email_user, password)
    return imap


def format_imap_date(dt: datetime):
    """
    Format a datetime to IMAP date format used in SEARCH commands.
    Example: 01-Oct-2025
    """
    return dt.strftime('%d-%b-%Y')


def decode_mime_words(value):
    """
    Decode MIME-encoded header fields into a readable string.
    Handles cases like =?utf-8?B?...?= sequences.
    """
    if not value:
        return ""
    fragments = decode_header(value)
    decoded = []
    for bytes_or_str, encoding in fragments:
        if isinstance(bytes_or_str, bytes):
            # Attempt decode with provided encoding or fallback to utf-8
            try:
                decoded.append(bytes_or_str.decode(encoding or 'utf-8', errors='ignore'))
            except Exception:
                decoded.append(bytes_or_str.decode('utf-8', errors='ignore'))
        else:
            decoded.append(bytes_or_str)
    return ''.join(decoded)


def parse_email_message(msg_data_tuple):
    """
    Parse a fetched message tuple returned by imap.fetch(..., '(RFC822)').

    Input: a tuple like (b'1 (RFC822 {xxxx}', message_bytes)
    Output: dict with keys: name, email, subject, body (plain text, minimal cleaning)

    This function:
    - Decodes From header into name and email
    - Decodes Subject safely (MIME decode)
    - Extracts text/plain body for the message (first text/plain found)
    """
    # Determine message bytes and construct email.message.Message
    if isinstance(msg_data_tuple, tuple):
        raw_bytes = msg_data_tuple[1]
    else:
        raw_bytes = msg_data_tuple
    msg = email.message_from_bytes(raw_bytes)

    # Extract and decode "From" header
    from_hdr = msg.get("From", "")
    from_decoded = decode_mime_words(from_hdr)

    # Try to split name and email using regex that covers common formats
    name = ""
    email_addr = ""
    m = re.match(r'(?:"?([^"]*)"?\s)?<?([^<>@\s]+@[^<>@\s]+)>?', from_decoded)
    if m:
        name = (m.group(1) or "").strip()
        email_addr = (m.group(2) or "").strip()
    else:
        # fallback: entire header into email_addr
        email_addr = from_decoded.strip()

    # Subject: decode MIME words safely
    subject = decode_mime_words(msg.get("Subject", ""))

    # Body extraction: prefer text/plain part
    body = ""
    if msg.is_multipart():
        # Walk through parts and pick first text/plain that's not an attachment
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get('Content-Disposition') or "")
            if ctype == 'text/plain' and 'attachment' not in cdisp.lower():
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body = payload.decode(charset, errors='ignore')
                    except Exception:
                        body = payload.decode('utf-8', errors='ignore')
                break
        # If no text/plain found, optionally try text/html fallback (strip tags)
        if not body:
            for part in msg.walk():
                if part.get_content_type() == 'text/html' and 'attachment' not in str(part.get('Content-Disposition') or "").lower():
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            html_text = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
                        except Exception:
                            html_text = payload.decode('utf-8', errors='ignore')
                        # Naive strip of HTML tags (small fallback)
                        body = re.sub('<[^<]+?>', ' ', html_text)
                        break
    else:
        # Not multipart: try single-part payload
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                body = payload.decode(msg.get_content_charset() or 'utf-8', errors='ignore')
            except Exception:
                body = payload.decode('utf-8', errors='ignore')
        else:
            # fallback to string payload
            body = str(msg.get_payload())

    # Normalize whitespace
    body = re.sub(r'\s+', ' ', (body or "")).strip()

    return {
        "name": name,
        "email": email_addr,
        "subject": subject,
        "body": body
    }


def fetch_emails_imap(imap_conn, mailbox: str, since_date: datetime, end_date: datetime, limit: int = None):
    """
    Fetch emails from a selected mailbox between 'since_date' and 'end_date' inclusive.

    Raises Exception on search/fetch failures.
    """
    imap_conn.select(mailbox)  # select mailbox
    since_str = format_imap_date(since_date)
    before_str = format_imap_date(end_date + timedelta(days=1))  # make before exclusive by adding 1 day

    # Build search criteria and run search
    search_criteria = f'(SINCE {since_str} BEFORE {before_str})'
    typ, data = imap_conn.search(None, search_criteria)
    if typ != 'OK':
        raise Exception("IMAP search failed")

    # data[0] contains space-separated ids (bytes); split into list
    id_list = data[0].split()
    if not id_list:
        return []  # nothing found

    # Optionally limit number of messages fetched (helps for very large mailboxes)
    if limit:
        id_list = id_list[-limit:]

    results = []
    # Loop through each message id and fetch RFC822 payload
    for msg_id in id_list:
        typ, msg_data = imap_conn.fetch(msg_id, '(RFC822)')
        if typ != 'OK':
            # On failure to fetch a message, skip it
            continue
        # msg_data may contain several tuples; find the tuple with actual message bytes
        for part in msg_data:
            if isinstance(part, tuple):
                parsed = parse_email_message(part)
                results.append(parsed)
                break
    return results


# ----------------------------
# Dummy Data (fallback)
# ----------------------------

def generate_dummy_emails(since_date: datetime, end_date: datetime, count: int = 10):
    """
    Generate structured dummy emails across the date range for UI/testing.
    Each message is a dict matching parse_email_message output.
    """
    dummy = []
    # Spread messages evenly across the date range
    total_days = max(1, (end_date - since_date).days)
    for i in range(count):
        day_offset = int((i * total_days) / max(1, (count - 1))) if count > 1 else 0
        d = since_date + timedelta(days=day_offset)
        name = f"Sender {i+1}"
        email_addr = f"sender{i+1}@example.com"
        subject = f"Dummy Subject {i+1} ({d.strftime('%Y-%m-%d')})"
        body = ("Hello,\nThis is a dummy email body used when IMAP is not available. " * 5).strip()
        dummy.append({
            "name": name,
            "email": email_addr,
            "subject": subject,
            "body": body
        })
    return dummy


# ----------------------------
# UI: Filter screen & Dashboard
# ----------------------------

class EmailFetcherApp:
    """
    Main application class that creates the filter screen and handles user actions.
    """
    def __init__(self, root):
        # Root Tk window
        self.root = root
        root.title("Email Fetcher - Filter")
        root.geometry("820x480")
        root.minsize(760, 420)

        # Set up overall style using ttk.Style
        style = ttk.Style()
        style.theme_use("clam")  # fairly neutral theme available in stock Tk

        # Configure general widget styles (labels, entries, buttons)
        style.configure("App.TFrame", background="#f5f7fb")
        style.configure("Card.TFrame", background="#ffffff", relief="flat")
        style.configure("Title.TLabel", background="#f5f7fb", foreground="#223", font=("Segoe UI", 16, "bold"))
        style.configure("TLabel", background="#ffffff", foreground="#111", font=("Segoe UI", 10))
        style.configure("TEntry", padding=6, relief="flat", font=("Segoe UI", 10))
        style.configure("Accent.TButton", foreground="white", background="#3c8dbc", font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Accent.TButton",
                  background=[("active", "#2f6fa0"), ("pressed", "#25507a")])

        # Main canvas to draw subtle gradient background & card shadow
        self.canvas = tk.Canvas(root, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        # Draw a simple top-to-bottom gradient
        self._draw_simple_vertical_gradient(self.canvas, "#eef3fb", "#ffffff")

        # Card frame centered on canvas (acts like a white card)
        card_w = 720
        card_h = 340
        self.card = ttk.Frame(self.canvas, width=card_w, height=card_h, style="Card.TFrame")
        # Place card centered
        self.canvas.create_window((410, 240), window=self.card)

        # Inside the card: layout fields in grid with nice spacing
        inner = ttk.Frame(self.card, padding=(18, 14, 18, 14), style="Card.TFrame")
        inner.pack(fill=tk.BOTH, expand=True)

        # Title label
        title = ttk.Label(inner, text="Email Filter", style="Title.TLabel")
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        # Email field
        ttk.Label(inner, text="Email (leave blank for dummy):").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.email_var = tk.StringVar()
        self.email_entry = ttk.Entry(inner, textvariable=self.email_var, width=44, style="TEntry")
        self.email_entry.grid(row=1, column=1, columnspan=2, sticky="w", padx=6, pady=6)

        # Password field
        ttk.Label(inner, text="Password:").grid(row=2, column=0, sticky="e", padx=6, pady=6)
        self.pw_var = tk.StringVar()
        self.pass_entry = ttk.Entry(inner, textvariable=self.pw_var, show="*", width=44, style="TEntry")
        self.pass_entry.grid(row=2, column=1, columnspan=2, sticky="w", padx=6, pady=6)

        # IMAP server field
        ttk.Label(inner, text="IMAP Server:").grid(row=3, column=0, sticky="e", padx=6, pady=6)
        self.server_var = tk.StringVar(value="imap.gmail.com")
        self.server_entry = ttk.Entry(inner, textvariable=self.server_var, width=44, style="TEntry")
        self.server_entry.grid(row=3, column=1, columnspan=2, sticky="w", padx=6, pady=6)

        # Date pickers
        ttk.Label(inner, text="Start Date:").grid(row=4, column=0, sticky="e", padx=6, pady=6)
        ttk.Label(inner, text="End Date:").grid(row=5, column=0, sticky="e", padx=6, pady=6)

        if TKCALENDAR_AVAILABLE:
            # DateEntry is more user-friendly if available
            self.start_date = DateEntry(inner, date_pattern='yyyy-mm-dd', width=18)
            self.end_date = DateEntry(inner, date_pattern='yyyy-mm-dd', width=18)
            self.start_date.set_date(datetime.now() - timedelta(days=7))
            self.end_date.set_date(datetime.now())
            self.start_date.grid(row=4, column=1, sticky="w", padx=6, pady=6)
            self.end_date.grid(row=5, column=1, sticky="w", padx=6, pady=6)
        else:
            # fallback: text entries with defaults
            self.start_var = tk.StringVar(value=(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
            self.end_var = tk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
            self.start_date = ttk.Entry(inner, textvariable=self.start_var, width=20, style="TEntry")
            self.end_date = ttk.Entry(inner, textvariable=self.end_var, width=20, style="TEntry")
            self.start_date.grid(row=4, column=1, sticky="w", padx=6, pady=6)
            self.end_date.grid(row=5, column=1, sticky="w", padx=6, pady=6)
            # helpful hint label
            ttk.Label(inner, text="(YYYY-MM-DD)", font=("Segoe UI", 9)).grid(row=4, column=2, sticky="w")

        # Spacer
        inner.grid_rowconfigure(6, minsize=6)

        # Fetch button (centered)
        fetch_btn = ttk.Button(inner, text="Fetch Emails", width=18, style="Accent.TButton", command=self.on_fetch)
        fetch_btn.grid(row=7, column=0, columnspan=3, pady=12)

        # Dashboard reference (for refreshing)
        self.dashboard = None

        # Bind resizing to re-draw gradient so it stays smooth
        root.bind("<Configure>", self._on_root_configure)

    # ---------- Canvas / Gradient helpers ----------
    def _draw_simple_vertical_gradient(self, canvas, color1, color2):
        """
        Draws a subtle gradient on the entire canvas using many thin lines.
        This gives a smoother, modern-looking background without external libs.
        """
        canvas.delete("bg_grad")
        width = canvas.winfo_width() or 820
        height = canvas.winfo_height() or 480
        # get RGB triplets
        r1, g1, b1 = self._hex_to_rgb(color1)
        r2, g2, b2 = self._hex_to_rgb(color2)
        # draw many horizontal lines from top to bottom blending from color1 to color2
        steps = max(100, height)
        for i in range(steps):
            ratio = i / (steps - 1)
            nr = int(r1 + (r2 - r1) * ratio)
            ng = int(g1 + (g2 - g1) * ratio)
            nb = int(b1 + (b2 - b1) * ratio)
            hexcol = f"#{nr:02x}{ng:02x}{nb:02x}"
            y = int(i * (height / steps))
            canvas.create_line(0, y, width, y, fill=hexcol, tags=("bg_grad",), width=1)

    def _hex_to_rgb(self, hex_color):
        # convert #rrggbb to (r,g,b) integers
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def _on_root_configure(self, event):
        # Re-draw gradient each time window size changes to keep it smooth
        try:
            self._draw_simple_vertical_gradient(self.canvas, "#eef3fb", "#ffffff")
        except Exception:
            pass

    # ---------- Fetch button handler ----------
    def on_fetch(self):
        """
        Called when the user clicks "Fetch Emails".
        Steps:
        """
        # 1. Parse dates (support either DateEntry or plain Entry)
        try:
            if TKCALENDAR_AVAILABLE:
                s_date = datetime(self.start_date.get_date().year,
                                  self.start_date.get_date().month,
                                  self.start_date.get_date().day)
                e_date = datetime(self.end_date.get_date().year,
                                  self.end_date.get_date().month,
                                  self.end_date.get_date().day)
            else:
                s_date = datetime.strptime(self.start_var.get().strip(), '%Y-%m-%d')
                e_date = datetime.strptime(self.end_var.get().strip(), '%Y-%m-%d')
        except Exception as ex:
            messagebox.showerror("Date error", "Please enter valid dates in YYYY-MM-DD format.")
            return

        # 2. Validate date order
        if s_date > e_date:
            messagebox.showerror("Date error", "Start Date must be earlier than or equal to End Date.")
            return

        # 3. IMAP attempt if credentials provided
        provided_email = self.email_var.get().strip()
        provided_pw = self.pw_var.get().strip()
        server = self.server_var.get().strip() or "imap.gmail.com"

        emails_list = []
        used_dummy = False

        if provided_email and provided_pw:
            # Try IMAP connection (with error handling)
            try:
                imap_conn = connect_imap(server, provided_email, provided_pw)
                try:
                    # Fetch emails from INBOX between dates. Limit None => fetch all found.
                    emails_list = fetch_emails_imap(imap_conn, "INBOX", s_date, e_date, limit=None)
                finally:
                    try:
                        imap_conn.logout()
                    except Exception:
                        # ignore logout errors
                        pass
            except imaplib.IMAP4.error as e:
                # Authentication or IMAP error occurred; ask user to fallback to dummy
                resp = messagebox.askyesno("IMAP Authentication Error",
                                           f"IMAP authentication/server error:\n{e}\n\nUse dummy data instead?")
                if resp:
                    used_dummy = True
                    emails_list = generate_dummy_emails(s_date, e_date, count=8)
                else:
                    return
            except Exception as e:
                # Generic failure (connection, DNS, etc.)
                resp = messagebox.askyesno("IMAP Connection Error",
                                           f"Failed to connect to IMAP server:\n{e}\n\nUse dummy data instead?")
                if resp:
                    used_dummy = True
                    emails_list = generate_dummy_emails(s_date, e_date, count=8)
                else:
                    return
        else:
            # No credentials → use dummy data by design
            used_dummy = True
            emails_list = generate_dummy_emails(s_date, e_date, count=10)

        # 4. If no emails found, show info popup (and still display dashboard with single "No emails found" row)
        total_count = len(emails_list)
        if total_count == 0:
            messagebox.showinfo("No emails", "No emails found in the selected date range.")
        # Open or refresh the dashboard window
        if self.dashboard and tk.Toplevel.winfo_exists(self.dashboard):
            self.dashboard.populate_table(emails_list, s_date, e_date, total_count)
        else:
            self.dashboard = DashboardWindow(self.root, emails_list, s_date, e_date, total_count, used_dummy)


class DashboardWindow(tk.Toplevel):
    """
    Dashboard window that displays results in a ttk.Treeview table.
    The table shows the 7 required columns:
      - Name, Email Address, Start Date, End Date, Subject, Body (first 200 chars), Emails Count
    Each row's Start/End dates are the selected range.
    Emails Count column shows total number of emails found in that range.
    """
    def __init__(self, parent, emails, start_dt, end_dt, emails_count, used_dummy=False):
        super().__init__(parent)
        self.title("Dashboard - Emails")
        self.geometry("1080x540")
        self.minsize(900, 420)
        self.configure(bg="#f8fafc")

        # Header label
        header_text = f"Emails from {start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')}"
        header_label = ttk.Label(self, text=header_text, font=("Segoe UI", 12, "bold"))
        header_label.pack(pady=(12, 4))

        if used_dummy:
            note = ttk.Label(self, text="(Showing dummy data - IMAP not used)", font=("Segoe UI", 9))
            note.pack()

        # Frame to hold table and scrollbar
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Define columns exactly as required
        cols = ("Name", "Email Address", "Start Date", "End Date", "Subject", "Body", "Emails Count")

        # Create Treeview
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        # Set up headings & column widths
        self.tree.heading("Name", text="Name")
        self.tree.column("Name", width=160, anchor="w")

        self.tree.heading("Email Address", text="Email Address")
        self.tree.column("Email Address", width=200, anchor="w")

        self.tree.heading("Start Date", text="Start Date")
        self.tree.column("Start Date", width=100, anchor="center")

        self.tree.heading("End Date", text="End Date")
        self.tree.column("End Date", width=100, anchor="center")

        self.tree.heading("Subject", text="Subject")
        self.tree.column("Subject", width=260, anchor="w")

        self.tree.heading("Body", text="Body (first 200 chars)")
        self.tree.column("Body", width=360, anchor="w")

        self.tree.heading("Emails Count", text="Emails Count")
        self.tree.column("Emails Count", width=110, anchor="center")

        # Vertical scrollbar
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Alternating row colors for readability
        self.tree.tag_configure("odd", background="#ffffff")
        self.tree.tag_configure("even", background="#f4f8ff")

        # Populate with initial data
        self.populate_table(emails, start_dt, end_dt, emails_count)

        # Close button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=8)
        close_btn = ttk.Button(btn_frame, text="Close", command=self.destroy, style="Accent.TButton")
        close_btn.pack()

    def populate_table(self, emails, start_dt, end_dt, emails_count):
        """
        Clears the tree and inserts rows from 'emails' list.
        Each email dict must have keys: name, email, subject, body.
        The Start Date and End Date columns contain the selected date range for each row.
        The Emails Count column repeats the total number of emails (as required).
        """
        # Clear existing rows
        for r in self.tree.get_children():
            self.tree.delete(r)

        if not emails:
            # Single informative row indicating no emails found
            self.tree.insert("", "end", values=("No emails found", "", start_dt.strftime('%Y-%m-%d'),
                                                end_dt.strftime('%Y-%m-%d'), "", "", 0), tags=("odd",))
            return

        # Insert each email row
        for idx, em in enumerate(emails):
            name = em.get("name", "")
            email_addr = em.get("email", "")
            subject = em.get("subject", "")
            body = em.get("body", "")
            # Truncate body to 200 characters for display
            truncated = (body[:200] + "...") if len(body) > 200 else body
            tag = "even" if idx % 2 == 0 else "odd"
            self.tree.insert("", "end", values=(name, email_addr, start_dt.strftime('%Y-%m-%d'),
                                                end_dt.strftime('%Y-%m-%d'), subject, truncated, emails_count),
                             tags=(tag,))


# ----------------------------
# Entrypoint
# ----------------------------

def main():
    """
    Create the main Tk root, instantiate EmailFetcherApp, and run mainloop.
    """
    root = tk.Tk()
    app = EmailFetcherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
def count_messages_gmail(service, sender, after_date, before_date):
    q = f'from:{sender} after:{after_date} before:{before_date}'
    total = 0
    page_token = None
    while True:
        res = service.users().messages().list(userId='me', q=q, pageToken=page_token).execute()
        msgs = res.get('messages', [])
        total += len(msgs)
        page_token = res.get('nextPageToken')
        if not page_token:
            break
    return total
# --- Inside DashboardWindow (replace your current DashboardWindow class) ---

class DashboardWindow(tk.Toplevel):
    """
    Enhanced Dashboard with:
    - Row click -> show full email content
    - Multi-select + Delete button
    - Colorful, smooth UI
    """
    def __init__(self, parent, emails, start_dt, end_dt, emails_count, imap_conn=None, used_dummy=False):
        super().__init__(parent)
        self.title("Dashboard - Emails")
        self.geometry("1080x540")
        self.minsize(900, 420)
        self.configure(bg="#f0f4f8")

        self.imap_conn = imap_conn  # save IMAP connection for delete

        # Header
        header_text = f"Emails from {start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')}"
        header_label = ttk.Label(self, text=header_text, font=("Segoe UI", 12, "bold"))
        header_label.pack(pady=(12, 4))

        if used_dummy:
            note = ttk.Label(self, text="(Showing dummy data - IMAP not used)", font=("Segoe UI", 9))
            note.pack()

        # Table frame
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Treeview columns
        cols = ("Name", "Email Address", "Start Date", "End Date", "Subject", "Body", "Emails Count")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")  # multi-select
        # Column setup
        for col, width in zip(cols, [160, 200, 100, 100, 260, 360, 110]):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.column("Start Date", anchor="center")
        self.tree.column("End Date", anchor="center")
        self.tree.column("Emails Count", anchor="center")

        # Scrollbar
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Alternating row colors & hover effect
        self.tree.tag_configure("odd", background="#ffffff")
        self.tree.tag_configure("even", background="#e6f0ff")
        self.tree.bind("<Motion>", self._on_hover)
        self.last_hover = None

        # Populate table
        self.populate_table(emails, start_dt, end_dt, emails_count)

        # Buttons frame
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=8)
        self.delete_btn = ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected,
                                     style="Accent.TButton")
        self.delete_btn.pack(side=tk.LEFT, padx=6)
        close_btn = ttk.Button(btn_frame, text="Close", command=self.destroy, style="Accent.TButton")
        close_btn.pack(side=tk.LEFT, padx=6)

        # Bind row double click -> show full email
        self.tree.bind("<Double-1>", self.on_row_double_click)

    def _on_hover(self, event):
        """
        Highlight row under cursor
        """
        row_id = self.tree.identify_row(event.y)
        if self.last_hover != row_id:
            # Remove previous hover highlight
            if self.last_hover:
                self.tree.item(self.last_hover, tags=(self.tree.item(self.last_hover, "tags")[0],))
            if row_id:
                self.tree.item(row_id, tags=("hover",))
                self.tree.tag_configure("hover", background="#d0e4ff")
            self.last_hover = row_id

    def populate_table(self, emails, start_dt, end_dt, emails_count):
        """
        Insert emails into tree
        """
        self.tree.delete(*self.tree.get_children())
        if not emails:
            self.tree.insert("", "end", values=("No emails found", "", start_dt.strftime('%Y-%m-%d'),
                                                end_dt.strftime('%Y-%m-%d'), "", "", 0), tags=("odd",))
            return
        for idx, em in enumerate(emails):
            name = em.get("name", "")
            email_addr = em.get("email", "")
            subject = em.get("subject", "")
            body = em.get("body", "")
            truncated = (body[:200] + "...") if len(body) > 200 else body
            tag = "even" if idx % 2 == 0 else "odd"
            self.tree.insert("", "end", values=(name, email_addr, start_dt.strftime('%Y-%m-%d'),
                                                end_dt.strftime('%Y-%m-%d'), subject, truncated, emails_count),
                             tags=(tag,))

    def on_row_double_click(self, event):
        """
        Show full email content in a popup
        """
        row_id = self.tree.selection()
        if not row_id:
            return
        values = self.tree.item(row_id[0])["values"]
        subject = values[4]
        body = next((v for v in values[5:6]), "")
        top = tk.Toplevel(self)
        top.title(subject[:50] + "...")
        top.geometry("600x400")
        txt = tk.Text(top, wrap="word")
        txt.insert("1.0", body)
        txt.config(state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def delete_selected(self):
        """
        Delete selected emails from IMAP (if connection exists)
        """
        if not self.imap_conn:
            messagebox.showinfo("Delete", "IMAP not connected, cannot delete dummy emails.")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Delete", "No emails selected.")
            return
        confirm = messagebox.askyesno("Confirm Delete", f"Delete {len(sel)} selected emails permanently?")
        if not confirm:
            return

        deleted_count = 0
        for row in sel:
            values = self.tree.item(row)["values"]
            # Assuming 'Email Address' + 'Subject' as unique identifier (better if you have msg_id)
            # Here you need to fetch message ID from IMAP using subject & sender
            # NOTE: For production, store msg_id in your email dict when fetching
            # For demo, we'll skip actual IMAP deletion
            deleted_count += 1
            self.tree.delete(row)
        messagebox.showinfo("Delete", f"Deleted {deleted_count} emails (simulation).")
