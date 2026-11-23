"""Diagram metadata for the command-and-control, exfiltration and collection actions (META-A).

Each entry states only what the action's code emits: ports, protocols, cadence, sizes and names were read from
``c2.py``, ``data.py``, ``exfil.py`` and ``delivery.py``. Behaviour only; wording is neutral ("the sensor").
Filter templates use ``{src_ip}`` ``{dst_ip}`` ``{fqdn}`` and ``{p:NAME}``.
"""

META = {
    # ------------------------------------------------------------------ command-and-control
    "https_beacon": {
        "plain": "A workstation phones home to an outside server over encrypted web traffic every minute or so, sending a "
                 "small request and getting a small reply. Defenders look for the steady rhythm hidden inside normal-looking HTTPS.",
        "tells": ["One short TLS session per check-in, on a steady period with about 20 percent jitter",
                  "Same destination and a fixed request look each time; replies of 180 to 900 bytes",
                  "A DNS lookup of the server name comes first, then TCP 443"],
        "filters": [("TLS sessions to the C2 name", 'ip.src == {src_ip} && tls.handshake.extensions_server_name == "{fqdn}"',
                     "One ClientHello per check-in, evenly spaced"),
                    ("Port 443 flows to the host", 'ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 443 && tcp.flags.syn == 1 && tcp.flags.ack == 0',
                     "A new connection every minute or so, evenly spaced")],
        "wire": "DNS then TLS 1.2, tcp/443, outbound, one small request and a 180 to 900 byte reply per check-in",
    },
    "http_beacon": {
        "plain": "A workstation checks in with an outside server using unencrypted web requests on port 80, on a repeating "
                 "schedule. Because it is plain text, a defender can read the path and headers and see the repeating pattern.",
        "tells": ["Short TCP 80 sessions on a jittered period, one request and one reply each",
                  "The same few URI paths and one user agent repeat; GET, POST or alternating",
                  "Cookie value is long random text when the profile sets one"],
        "filters": [("Requests to the C2 host", 'ip.src == {src_ip} && http.host == "{fqdn}"',
                     "Requests at an even interval with the same paths"),
                    ("Repeating port 80 requests", 'ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 80 && http.request',
                     "Same few URIs and one user agent each time")],
        "wire": "DNS then HTTP, tcp/80, outbound, small request (POST body 60 to 240 B), 120 to 700 B reply",
    },
    "dns_beacon": {
        "plain": "A workstation checks in with its controller by asking DNS questions about made-up names under the "
                 "controller's domain, one every minute or so. Defenders see it as a clockwork rhythm of equal-length odd names.",
        "tells": ["One query per period, each name a random label of the same length under one domain",
                  "Default query type is TXT, answered by the domain's own server with a tiny record",
                  "No two names repeat, so the resolver never gets a cache hit"],
        "filters": [("Queries under the C2 domain", 'ip.src == {src_ip} && dns.qry.name contains "{fqdn}"',
                     "One query per period, equal-length leading label"),
                    ("Label length matches setting", 'ip.src == {src_ip} && dns.qry.name.len >= {p:label_len}',
                     "Names at least as long as the label length")],
        "wire": "DNS, udp/53, to resolver, one fixed-length-label query per interval, tiny answer",
    },
    "dns_tunnel": {
        "plain": "A workstation pushes data through DNS lookups by packing it into very long random-looking names, "
                 "in quick bursts. Defenders notice the name length, the randomness and the burst rate, none of which resemble real lookups.",
        "tells": ["Bursts of 25 queries 50 to 250 ms apart, then a pause of about 30 s",
                  "Each name carries two labels of 60 random characters, so names run past 120 characters",
                  "TXT answers hold base64 text; all queries go to one domain"],
        "filters": [("Very long query names", 'ip.src == {src_ip} && dns.qry.name.len > 100',
                     "Names well over 100 characters in rapid runs"),
                    ("TXT queries to the C2 domain", 'ip.src == {src_ip} && dns.qry.type == 16 && dns.qry.name contains "{fqdn}"',
                     "Hundreds of unique TXT names to one domain")],
        "wire": "DNS, udp/53, client to resolver, bursts of 25 queries with names over 120 bytes, base64 TXT answers",
    },
    "dga_lookup": {
        "plain": "A workstation tries a string of random-looking domain names, nearly all of which do not exist, until one "
                 "answers. Defenders watch for the burst of failed lookups because normal software rarely asks for names like these.",
        "tells": ["About eight random 10 to 16 character names in under a few seconds, all NXDOMAIN",
                  "Names mix letters and digits under TLDs like top, xyz, info, net, com, online",
                  "One last lookup is different: it resolves to the destination address"],
        "filters": [("Failed lookups from the host", 'ip.dst == {src_ip} && dns.flags.rcode == 3',
                     "A burst of NXDOMAIN replies in a few seconds"),
                    ("Queries from the host", 'ip.src == {src_ip} && dns.flags.response == 0 && dns.qry.name.len > 12',
                     "Random-looking names, none repeated")],
        "wire": "DNS, udp/53, to resolver, burst of small queries 0.05 to 0.5 s apart, NXDOMAIN replies",
    },
    "tor_connect": {
        "plain": "A workstation opens one long encrypted connection straight to an IP address that carries anonymising "
                 "relay traffic. Defenders care because it hides where the host is really talking and bypasses web controls.",
        "tells": ["No DNS lookup beforehand; the relay is reached by IP address",
                  "Random www.<name>.com server name; self-signed certificate under a random .net name",
                  "Records are exact multiples of 514 bytes, in both directions, for the whole connection"],
        "filters": [("TLS to the relay address", 'ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == {p:port} && tls.handshake.type == 1',
                     "A ClientHello with a random www.<name>.com name"),
                    ("Server name looks random", 'ip.src == {src_ip} && tls.handshake.extensions_server_name matches "^www\\\\.[a-z2-7]+\\\\.com$"',
                     "A server name of random base32 letters")],
        "wire": "TLS, tcp/443 (or 9001), both ways, one connection of about 120 s, 514-byte multiples",
    },
    "icmp_tunnel": {
        "plain": "A workstation hides a conversation inside ping packets whose contents are random and keep changing size. "
                 "Defenders look for echo traffic that is far larger and more varied than a normal ping.",
        "tells": ["Echo requests once a second with one identifier and a rising sequence number",
                  "Payloads vary from 64 to 900 bytes and are random, not the fixed printable fill of ping",
                  "Reply size is drawn separately, so it usually differs"],
        "filters": [("Large echo requests", 'ip.src == {src_ip} && ip.dst == {dst_ip} && icmp.type == 8 && data.len > 64',
                     "Requests with payloads of varying length"),
                    ("Echo replies from the peer", 'ip.src == {dst_ip} && ip.dst == {src_ip} && icmp.type == 0',
                     "Reply sizes that differ from the requests")],
        "wire": "ICMP echo, no port, both ways, 120 requests one second apart, payloads 64 to 900 B",
    },
    "cloud_service_c2": {
        "plain": "A workstation polls what looks like a public web-service API for messages, using a service-style host name "
                 "so the traffic blends in. Defenders care because the destination looks legitimate and only the poll pattern gives it away.",
        "tells": ["The TLS server name is a service-style host name, not an unknown-looking domain",
                  "GETs of a channel path every 30 s with a bearer token; a small POST every fourth poll",
                  "Replies are short JSON, mostly empty, now and then a larger item"],
        "filters": [("Polls of the channel path", 'ip.src == {src_ip} && http.request.uri contains "{p:path_prefix}"',
                     "A GET of the same path on a fixed period"),
                    ("TLS to the service name", 'ip.src == {src_ip} && tls.handshake.extensions_server_name == "{fqdn}"',
                     "One long session, or one per poll if keepalive is off")],
        "wire": "DNS then TLS 1.2, tcp/443, outbound, small GETs and POSTs every 30 s, short JSON replies",
    },
    "payload_download": {
        "plain": "A workstation fetches a file from an outside server over a plain web request. The file looks like a program "
                 "or document but is inert filler. Defenders care because it is how tools get onto a host.",
        "tells": ["One GET followed by a single large 200 response of the stated size",
                  "Body starts with a file signature such as MZ, PK or %PDF, with a matching Content-Type",
                  "A Content-Disposition header names the file; the path often ends in that name"],
        "filters": [("Download request", 'ip.src == {src_ip} && http.request.method == "GET" && http.host == "{fqdn}"',
                     "A GET for a file path on the C2 host"),
                    ("Large file response", 'ip.src == {dst_ip} && ip.dst == {src_ip} && http.content_length >= 4096',
                     "A 200 with a file Content-Type (if not https)")],
        "wire": "DNS then HTTP tcp/80 (or TLS tcp/443 when scheme is https), small GET out, body 4 KB to 50 MB back",
    },

    # ------------------------------------------------------------------ exfiltration
    "https_upload": {
        "plain": "A workstation sends a large amount of data to an outside server in numbered chunks over an encrypted web "
                 "session. Defenders watch for hosts that send far more than they receive to a single outside address.",
        "tells": ["One TLS session of PUT or POST requests for /upload/part-0000, part-0001 and on",
                  "Parts start small and ramp up to the chunk size, each answered by a short 201 or 200",
                  "Outbound bytes far exceed inbound bytes for the whole session"],
        "filters": [("Part uploads", 'ip.src == {src_ip} && http.request.uri contains "{p:path}/part-"',
                     "Consecutive part numbers, when decrypted"),
                    ("Large outbound frames", 'ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 443 && tcp.len > 1000',
                     "Sustained one-way data towards the server")],
        "wire": "DNS then TLS 1.2, tcp/443, outbound bulk, parts ramp up to about 262 KB, 2 MB by default",
    },
    "cloud_storage_upload": {
        "plain": "A workstation uploads a big file in pieces to what looks like a cloud storage service, then tells the "
                 "service to stitch the pieces together. Defenders care because the destination is a trusted service type.",
        "tells": ["Initiate POST (?uploads), numbered PUTs with partNumber and uploadId, a closing POST",
                  "Each part is answered with a short 200 carrying an ETag header",
                  "The server name is a storage-style host, with the bucket name as a prefix when set"],
        "filters": [("Part uploads", 'ip.src == {src_ip} && http.request.method == "PUT" && http.request.uri contains "partNumber="',
                     "A run of PUTs with rising partNumber"),
                    ("Initiate and complete", 'ip.src == {src_ip} && http.request.method == "POST" && http.request.uri contains "upload"',
                     "One POST at the start and one at the end")],
        "wire": "DNS then TLS 1.2, tcp/443, outbound bulk, parts ramp up to about 512 KB, 3 MB total by default",
    },
    "dns_exfil": {
        "plain": "A workstation leaks data by asking DNS lookups whose names are long strings of random characters under an "
                 "outside domain. Defenders care because DNS is rarely blocked and each name can carry a small piece of data.",
        "tells": ["About 60 queries in roughly 10 s, each name three 63-character labels under one domain",
                  "Default type is A, so the answer is a tiny record while the question is large",
                  "Every name is unique, so none are cached"],
        "filters": [("Long names to one domain", 'ip.src == {src_ip} && dns.qry.name.len > 150 && dns.qry.name contains "{fqdn}"',
                     "Many unique names of 150+ characters"),
                    ("Query rate from the host", 'ip.src == {src_ip} && dns.flags.response == 0 && dns.qry.type == 1',
                     "About six or seven queries a second")],
        "wire": "DNS, udp/53, client to resolver, queries of about 200 bytes roughly 0.15 s apart, small A answers",
    },
    "ftp_upload": {
        "plain": "A workstation logs in to an outside FTP server and sends it a zip-looking file in clear text. Defenders "
                 "care because FTP to the internet is rare, and everything including the login is readable.",
        "tells": ["USER and PASS on port 21 in clear text, then TYPE I and PASV",
                  "Data connection to a high passive port, closed by the sender when the file ends",
                  "STOR names a backup_*.zip file whose bytes start with the zip signature"],
        "filters": [("FTP control commands", 'ip.src == {src_ip} && ip.dst == {dst_ip} && ftp.request.command == "STOR"',
                     "A STOR for a zip file after a login"),
                    ("Login in clear text", 'ip.src == {src_ip} && ftp.request.command == "USER" && ftp.request.arg == "{p:user}"',
                     "A USER command for the account on port 21")],
        "wire": "DNS then FTP, tcp/21 plus passive data port 49152 to 65499, outbound, 500 KB by default",
    },
    "smtp_exfil": {
        "plain": "A workstation emails a large attachment to an outside address by talking directly to a mail server in clear "
                 "text. Defenders care because ordinary users send mail through the company server, not straight out.",
        "tells": ["Direct SMTP on port 25 from a workstation, no STARTTLS and no login",
                  "MAIL FROM a company address, RCPT TO an outside one, then a DATA body of base64 text",
                  "The attachment is a zip-signature file split into 76-column lines"],
        "filters": [("SMTP commands to outside", 'ip.src == {src_ip} && ip.dst == {dst_ip} && smtp.req.command == "RCPT"',
                     "A RCPT TO for an outside recipient"),
                    ("Message body upload", 'ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 25 && tcp.len > 1000',
                     "Large one-way data after DATA")],
        "wire": "DNS then SMTP, tcp/25, outbound, about 1.5 MB attachment as 76-column base64 by default",
    },

    # ------------------------------------------------------------------ collection
    "archive_stage": {
        "plain": "On a file server, a host writes one or more large archive files into a temporary folder to gather data before "
                 "sending it out. Defenders care because big archive writes to a staging folder often come just before exfiltration.",
        "tells": ["SMB2 CREATE then many 1 MiB WRITEs into a Temp\\stage style directory",
                  "File names like backup_*, export_*, data_* with a zip, 7z or rar extension",
                  "The first write starts with the archive signature, the rest is incompressible"],
        "filters": [("SMB2 writes to the server", 'ip.src == {src_ip} && ip.dst == {dst_ip} && smb2.cmd == 9',
                     "A long run of large WRITE requests"),
                    ("Archive file names", 'ip.src == {src_ip} && smb2.filename contains ".{p:format}"',
                     "Creates of archive files in the staging path")],
        "wire": "SMB2 after Kerberos, tcp/445, client to server bulk, 1 MiB writes, 40 MB in one file by default",
    },
    "smb_collect": {
        "plain": "A host reads many files from a shared folder on an internal server in one sequence. Defenders look for one "
                 "workstation reading far more files than usual, since that is how data gets gathered before it leaves.",
        "tells": ["Directory listing first, then sequential reads of about a dozen files",
                  "Server to client bytes dominate, 20 MB by default",
                  "Kerberos-authenticated session to a single share"],
        "filters": [("SMB2 reads from the server", 'ip.src == {src_ip} && ip.dst == {dst_ip} && smb2.cmd == 8',
                     "A run of READ requests across many files"),
                    ("Directory listing", 'ip.src == {src_ip} && ip.dst == {dst_ip} && smb2.cmd == 14',
                     "A QUERY_DIRECTORY before the reads begin")],
        "wire": "SMB2 after Kerberos, tcp/445, server to client bulk, 1 MiB reads, 20 MB over 12 files by default",
    },
    "sql_collect": {
        "plain": "A host logs in to a database server and reads whole tables, thousands of rows at a time. Defenders care "
                 "because one client pulling far more rows than any application normally asks for suggests data theft.",
        "tells": ["TDS login, a table listing query, then SELECT * on several tables",
                  "Each result is thousands of rows sent in 64 KB bursts",
                  "A few seconds pass between statements; the account is a service-style name"],
        "filters": [("Database traffic from the host", 'ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 1433',
                     "One connection with a short query and long replies"),
                    ("Bulk replies", 'ip.src == {dst_ip} && ip.dst == {src_ip} && tcp.srcport == 1433 && tcp.len > 1000',
                     "Sustained large server-to-client segments")],
        "wire": "TDS, tcp/1433, short queries out, megabyte result sets back, one statement every few seconds",
    },
}
