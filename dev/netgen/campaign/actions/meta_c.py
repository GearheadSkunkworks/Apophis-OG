"""Diagram metadata (plain wording, tells, filters, wire summary) for 17 campaign actions (META-C).

Every statement is taken from the action code in host.py, outside.py and delivery.py. Filter templates use only
{src_ip} {dst_ip} {fqdn} and {p:NAME}; the user-agent strings inside filters are the bare strings that appear on
the wire."""

_SVC = "367abb81-9844-35f1-ad32-98f038001003"
_SCH = "86d35949-83c9-4044-b424-db363231fd0c"
_EVT = "82273fdc-e32a-18c3-3f78-827929dc23ea"

META = {
    # ------------------------------------------------------------------ initial-access
    "exposed_service_login": {
        "plain": "An internet host keeps trying to log on to a remote-access service (RDP or SSH) that faces the web. "
                 "Defenders care because a few tries succeed and a session stays open.",
        "tells": ["One short TCP connection per attempt, about 2.5 s apart, from one internet address",
                  "Most attempts end by reset, alert or an SSH auth failure after a 1 to 2 s delay",
                  "A late attempt stays up about 20 s with small two-way bursts"],
        "filters": [("RDP connection attempts", "ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
                     "one SYN per attempt, 14 by default"),
                    ("RDP account name in the request", "ip.src == {src_ip} && rdp.rt_cookie",
                     "a mstshash cookie, a different account per try"),
                    ("SSH client banner", "ip.src == {src_ip} && ssh.protocol contains \"libssh\"",
                     "client banner libssh_0.10.5 on each SSH try")],
        "wire": "RDP tcp/3389 (X.224, TLS, CredSSP) or SSH tcp/22, inbound, one connection per try, about 2.5 s apart",
    },
    "phishing_visit": {
        "plain": "A user opens a fake sign-in page and submits a form. The traffic looks like an ordinary web login, "
                 "so defenders watch for the unfamiliar site and a credential post.",
        "tells": ["DNS lookup, then HTTPS on 443 to a destination with no prior history",
                  "GET of a small plain sign-in page, then a POST to /login about 12 s later",
                  "The POST is answered 302 with a session cookie, then a GET of /account"],
        "filters": [("Lookup of the site", "dns.qry.name == \"{fqdn}\" && ip.src == {src_ip}", "one A query before the web session"),
                    ("Form submission", "ip.src == {src_ip} && http.request.method == \"POST\" && http.request.uri == \"/login\"",
                     "one POST with a form body (needs decryption)"),
                    ("Redirect after submit", "ip.src == {dst_ip} && http.response.code == 302 && http.location == \"/account\"",
                     "302 to /account with a Set-Cookie header")],
        "wire": "DNS udp/53, then HTTPS tcp/443 (or HTTP tcp/80), outbound, 3 requests, page about 1 KB, POST at 12 s",
    },
    "web_login_spray": {
        "plain": "An internet host posts many username and password pairs to one web login page, trying each password across "
                 "many accounts. Defenders see a burst of failed logins from one address, then one success.",
        "tells": ["24 form POSTs to one path over two TLS sessions, about 0.7 s apart per session",
                  "Nearly every reply is 401 with a small JSON error",
                  "One reply late in the run is 302 with a Set-Cookie header"],
        "filters": [("Login posts", "ip.src == {src_ip} && http.request.method == \"POST\"",
                     "one POST per pair, same path every time"),
                    ("Failed logins", "ip.src == {dst_ip} && http.response.code == 401", "a run of 401 replies"),
                    ("The success", "ip.src == {dst_ip} && http.response.code == 302 && http.set_cookie contains \"sid=\"",
                     "a single 302 with a session cookie")],
        "wire": "HTTPS tcp/443, inbound, 2 sessions, 24 POSTs of about 40 bytes, 401 JSON replies, about 0.7 s apart",
    },
    "exploit_probe": {
        "plain": "An internet host requests the characteristic page of a product named in a known-exploited vulnerability, then posts "
                 "a dummy form, and the server refuses. Defenders see the shape of an attempt against that product, with no exploit content.",
        "tells": ["One GET of the product's endpoint, then two form POSTs of about 7 bytes to its endpoints",
                  "The first reply is 200, the POST replies are 403 with a tiny body",
                  "A request header carries the CVE id (X-Request-Tag)"],
        "filters": [("Probe requests", "ip.src == {src_ip} && http.request.method == \"POST\"",
                     "two POSTs after the first GET"),
                    ("Refusals", "ip.src == {dst_ip} && http.response.code == 403", "a 403 for each POST"),
                    ("CVE tag", "http.request.line contains \"X-Request-Tag\"", "the CVE id on every request")],
        "wire": "HTTPS tcp/443 (HTTP tcp/80 for appliances), inbound, 3 requests: a 200, then two 403 replies",
    },
    # ------------------------------------------------------------------ execution
    "ssh_remote_exec": {
        "plain": "A host runs a one-line command on a Linux server over SSH, three times in a row, the way a script does. "
                 "Defenders care because the sessions are short, regular and automated.",
        "tells": ["Three SSH connections to tcp/22, about 6 s apart, each lasting about a second",
                  "Each runs key exchange, a three-step login, one exec request and a small reply",
                  "Everything after key exchange is encrypted; only sizes and timing show"],
        "filters": [("SSH connection starts", "ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
                     "one SYN per session, 3 by default"),
                    ("Key exchange start", "ip.src == {src_ip} && ssh.message_code == 20", "one KEXINIT from the client per session"),
                    ("Client banner", "ip.src == {src_ip} && ssh.protocol contains \"OpenSSH\"", "a stock client banner per session")],
        "wire": "SSH tcp/22, internal to server, 3 sessions about 6 s apart, each under 2 s, packets 52 to 140 bytes",
    },
    "winrm_exec": {
        "plain": "One host runs a short command on another over remote management (WinRM): open a shell, run the command, "
                 "read the reply, close. Defenders care because it is a common way to move between machines.",
        "tells": ["Six POSTs to /wsman on tcp/5985 over one connection, in a fixed order",
                  "Shell create, command, receive, signal, delete, ending in a delete of the shell",
                  "Plain mode shows every message; encrypted mode shows sealed blocks after a Kerberos ticket"],
        "filters": [("WinRM requests", "ip.src == {src_ip} && tcp.dstport == {p:port} && http.request.method == \"POST\" && http.request.uri == \"/wsman\"",
                     "a run of POSTs to /wsman on one connection"),
                    ("Client agent", "http.user_agent == \"Microsoft WinRM Client\" && ip.dst == {dst_ip}", "the same client agent string on each request"),
                    ("Shell commands in the clear", "ip.src == {src_ip} && http.file_data contains \"CommandLine\"",
                     "one command request in plain mode only")],
        "wire": "HTTP tcp/5985 (SOAP on /wsman), internal, one connection, 6 requests under 2 KB, about 1 s",
    },
    # ------------------------------------------------------------------ persistence
    "remote_schtask": {
        "plain": "A host creates a scheduled task on another machine over the network, runs it, and removes it about 20 s later. "
                 "Defenders care because a task that runs on its own is a way to stay on a machine.",
        "tells": ["SMB2 session, then the atsvc pipe opened on the IPC$ share",
                  "Bind to the task scheduler interface, then calls 1 (register), 12 (run), 13 (delete)",
                  "The task definition is sealed, about 1.8 KB in the register request"],
        "filters": [("Task scheduler bind", "dcerpc.cn_bind_to_uuid == " + _SCH + " && ip.src == {src_ip}", "one bind per run"),
                    ("The atsvc pipe", "smb2.filename == \"atsvc\" && ip.src == {src_ip}", "one pipe open on IPC$"),
                    ("Register call", "dcerpc.opnum == 1 && ip.src == {src_ip} && ip.dst == {dst_ip}", "the largest request, then run and delete calls")],
        "wire": "SMB2 tcp/445, DCERPC on atsvc pipe, internal, 3 calls, register about 1.9 KB, delete at 20 s",
    },
    "svcctl_persist": {
        "plain": "A host creates a new auto-start service on another machine over the network, then leaves without starting it. "
                 "Defenders care because a new service survives a reboot.",
        "tells": ["SMB2 session and the svcctl pipe opened on the IPC$ share",
                  "Calls 15 (open manager), 12 (create service), 0 (close) and no call 19 (start)",
                  "The create request is a few hundred bytes and sealed, so names stay hidden"],
        "filters": [("Service control bind", "dcerpc.cn_bind_to_uuid == " + _SVC + " && ip.src == {src_ip}", "one bind per run"),
                    ("Create service call", "svcctl.opnum == 12 && ip.src == {src_ip} && ip.dst == {dst_ip}", "one create call"),
                    ("No start call", "svcctl.opnum == 19 && ip.src == {src_ip}", "no packets (the service is never started)")],
        "wire": "SMB2 tcp/445, DCERPC on svcctl pipe, internal, 3 calls, create request about 300 B",
    },
    # ------------------------------------------------------------------ privilege-escalation
    "gpo_modify": {
        "plain": "A host changes a Group Policy object on a domain controller: it edits the directory entry and writes two "
                 "policy files. Defenders care because a policy change reaches every machine it links to.",
        "tells": ["LDAP search then modify requests to the policy container and the domain gPLink",
                  "SMB2 writes of GPT.INI and a settings template under the SYSVOL policies folder",
                  "The directory change follows the file writes by 0.05 to 0.4 s"],
        "filters": [("Directory modifications", "ip.src == {src_ip} && ip.dst == {dst_ip} && ldap.protocolOp == 6", "two modifyRequest messages"),
                    ("Link attribute", "ip.src == {src_ip} && ldap.protocolOp == 6 && ldap contains \"gPLink\"", "one modify naming gPLink"),
                    ("Policy file writes", "ip.src == {src_ip} && smb2.filename contains \"GPT.INI\"", "a create of GPT.INI under Policies")],
        "wire": "LDAP tcp/389 and SMB2 tcp/445 to a DC, internal, 2 modifies, 2 file writes under 200 B",
    },
    "privileged_group_add": {
        "plain": "A host adds an account to a powerful directory group, such as Domain Admins, with one directory change. "
                 "Defenders care because it quietly gives that account wide control.",
        "tells": ["LDAP lookups of the account and the group, then one modifyRequest adding a member",
                  "A read of the group right after shows the new member list",
                  "The whole exchange is one short Kerberos-bound LDAP session"],
        "filters": [("The change", "ip.src == {src_ip} && ip.dst == {dst_ip} && ldap.protocolOp == 6 && ldap contains \"member\"",
                     "one modifyRequest on the member attribute"),
                    ("Lookup of the group", "ip.src == {src_ip} && ldap.protocolOp == 3 && ldap contains \"{p:group}\"",
                     "a search naming the group, before and after"),
                    ("Directory session", "ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 389", "one connection to the domain controller")],
        "wire": "LDAP tcp/389, internal to a DC, one session, 2 searches, 1 modify, 1 read-back, under 3 KB",
    },
    # ------------------------------------------------------------------ stealth
    "eventlog_clear": {
        "plain": "A host clears the Security and System event logs on another machine over the network. "
                 "Defenders care because wiping logs erases the evidence of what came before.",
        "tells": ["SMB2 session and the eventlog pipe opened on the IPC$ share",
                  "For each log, calls 7 (open), 0 (clear) and 2 (close), in that order",
                  "Log names are sealed; the call numbers and their order are the signal"],
        "filters": [("Event log bind", "dcerpc.cn_bind_to_uuid == " + _EVT + " && ip.src == {src_ip}", "one bind per run"),
                    ("The eventlog pipe", "smb2.filename == \"eventlog\" && ip.src == {src_ip}", "one pipe open on IPC$"),
                    ("Clear calls", "eventlog.opnum == 0 && ip.src == {src_ip} && ip.dst == {dst_ip}", "one clear per log, 2 by default")],
        "wire": "SMB2 tcp/445, DCERPC on eventlog pipe, internal, 3 calls per log, small sealed stubs",
    },
    "lolbin_fetch": {
        "plain": "A built-in system tool downloads a file from the internet, using its own user-agent string. "
                 "Defenders care because a trusted tool fetching a program is hard to tell from routine use.",
        "tells": ["The user agent is the system component's own, not a browser's",
                  "One GET for a file of about 90 KB; the file is an inert body with a program header",
                  "The transfer-service look adds a HEAD probe, then a ranged GET answered 206"],
        "filters": [("Crypto-component fetch", "ip.src == {src_ip} && http.request.method == \"GET\" && http.user_agent contains \"CryptoAPI\"",
                     "a GET from the system crypto component"),
                    ("Transfer-service probe and range", "ip.src == {src_ip} && http.request.method == \"HEAD\" && http.user_agent contains \"BITS\"",
                     "HEAD, then a ranged GET answered 206"),
                    ("The download", "ip.src == {dst_ip} && http.content_length > 4000 && http.response.code == 200", "one large 200 reply")],
        "wire": "DNS, then HTTP tcp/80 (or tcp/443), outbound, 1 GET (or HEAD plus ranged GET), body about 90 KB",
    },
    # ------------------------------------------------------------------ defense-impairment
    "security_service_stop": {
        "plain": "A host stops three security services on another machine over the network. "
                 "Defenders care because shutting protection off usually comes before something worse.",
        "tells": ["SMB2 session and the svcctl pipe, then one open of the service manager (call 15)",
                  "For each of three services: open (16), stop control (1), status check (6), close (0)",
                  "Names are sealed; the repeating call pattern shows the stops"],
        "filters": [("Service control bind", "dcerpc.cn_bind_to_uuid == " + _SVC + " && ip.src == {src_ip}", "one bind per run"),
                    ("Stop control calls", "svcctl.opnum == 1 && ip.src == {src_ip} && ip.dst == {dst_ip}", "one per service, 3 by default"),
                    ("Service opens", "svcctl.opnum == 16 && ip.src == {src_ip}", "one per service")],
        "wire": "SMB2 tcp/445 with DCERPC on the svcctl pipe, internal to internal, 13 calls, small sealed stubs, 4 s",
    },
    "security_update_block": {
        "plain": "A host stops being able to reach its security-update server and keeps retrying every five minutes. "
                 "Defenders care because a protection tool that cannot update may have been cut off on purpose.",
        "tells": ["The same name is looked up every 300 s (10 percent jitter)",
                  "Each lookup is followed by a TCP 443 attempt that is reset or goes unanswered",
                  "No connection ever finishes; unanswered tries repeat the SYN at 1, 2 and 4 s"],
        "filters": [("Update lookups", "ip.src == {src_ip} && dns.qry.name == \"{p:domain}\"", "one query per cycle, 6 by default"),
                    ("Refused connections", "ip.src == {dst_ip} && tcp.srcport == 443 && tcp.flags.reset == 1", "resets from the server on refused cycles"),
                    ("Unanswered attempts", "ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == 443 && tcp.analysis.retransmission",
                     "repeated SYNs with no reply")],
        "wire": "DNS udp/53, then TCP tcp/443 refused or unanswered, outbound, one cycle every 300 s (jittered)",
    },
    # ------------------------------------------------------------------ resource-development
    "new_domain_contact": {
        "plain": "A host reaches a website whose domain and certificate were set up minutes earlier, and makes two visits. "
                 "Defenders care because new infrastructure is often attacker-controlled.",
        "tells": ["DNS answer with a 60 s lifetime, then HTTPS to the same address",
                  "The server certificate was issued about 12 minutes before the first visit, valid 90 days",
                  "Two visits about 20 s apart, each a GET of / answered with a tiny page"],
        "filters": [("Short-lived answer", "dns.qry.name == \"{fqdn}\" && dns.resp.ttl == 60", "an A answer with a 60 s TTL"),
                    ("The certificate", "tls.handshake.type == 11 && ip.src == {dst_ip}", "a certificate whose notBefore is minutes old"),
                    ("Server name", "ip.src == {src_ip} && tls.handshake.extensions_server_name == \"{fqdn}\"", "one ClientHello per visit")],
        "wire": "DNS udp/53, then HTTPS tcp/443, outbound, 2 visits about 20 s apart, reply page under 200 bytes",
    },
    "selfsigned_tls_contact": {
        "plain": "A host checks in over TLS to a server that presents a self-made certificate on port 8443. "
                 "Defenders care because legitimate services rarely use untrusted certificates on odd ports.",
        "tells": ["Three TLS 1.2 sessions to tcp/8443, about 45 s apart (30 percent jitter)",
                  "The server certificate is its own issuer and untrusted",
                  "Each session is one small request (120 to 420 bytes) and a reply of 200 to 1200 bytes"],
        "filters": [("Check-in connections", "ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.dstport == {p:port} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
                     "one SYN per session, 3 by default"),
                    ("Server certificate", "ip.src == {dst_ip} && tcp.srcport == {p:port} && tls.handshake.type == 11", "a certificate with issuer equal to subject"),
                    ("Server name", "ip.src == {src_ip} && tls.handshake.extensions_server_name == \"{fqdn}\"", "one ClientHello per session")],
        "wire": "TLS 1.2 tcp/8443, outbound, 3 sessions about 45 s apart, request 120-420 B, reply 200-1200 B",
    },
    # ------------------------------------------------------------------ reconnaissance
    "subdomain_enum": {
        "plain": "An internet host guesses sub-names of the company's public domain, such as vpn or mail, to find what exists. "
                 "Defenders care because the guesses map targets before an attack.",
        "tells": ["Apex lookups (SOA, NS, MX, TXT), then a zone-transfer try on tcp/53 that is refused",
                  "About 60 A queries at 15 per second; most come back NXDOMAIN",
                  "Six names answer with an address in the 203.0.113 documentation range"],
        "filters": [("Guessing queries", "ip.src == {src_ip} && ip.dst == {dst_ip} && dns.flags.response == 0 && dns.qry.type == 1",
                     "a fast run of A queries for new sub-names"),
                    ("Misses", "ip.src == {dst_ip} && dns.flags.rcode == 3", "most replies are NXDOMAIN"),
                    ("Zone transfer try", "ip.src == {src_ip} && tcp.dstport == 53 && dns.qry.type == 252", "one AXFR query, refused")],
        "wire": "DNS udp/53 plus one tcp/53 transfer try, inbound, about 60 queries at 15 per second",
    },
    "web_dir_scan": {
        "plain": "An internet host requests a list of common page names, such as admin and login, to find hidden parts of a web server. "
                 "Defenders see a flood of not-found replies from one address.",
        "tells": ["60 GETs at about 25 per second over four keep-alive connections",
                  "Almost every reply is the same-size 404; a few are 200, 301, 302, 401 or 403",
                  "A single scanner-style user agent is on every request"],
        "filters": [("Scanner requests", "ip.src == {src_ip} && http.user_agent == \"{p:user_agent}\" && http.request.method == \"GET\"",
                     "the same agent on every GET"),
                    ("Misses", "ip.src == {dst_ip} && http.response.code == 404", "most replies are 404"),
                    ("Paths that exist", "ip.src == {dst_ip} && (http.response.code == 200 || http.response.code == 302 || http.response.code == 401 || http.response.code == 403)",
                     "a handful of non-404 replies")],
        "wire": "HTTP tcp/80 (HTTPS tcp/443 if set), inbound, 4 connections, 60 GETs at 25 per second, 404 replies",
    },
}
