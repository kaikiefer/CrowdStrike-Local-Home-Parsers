// UniFi Network / Protect / OS. CPS 1.2.0, ECS 9.5.0.
// One raw syslog/CEF event per input. Keep vendor fields and @rawstring.

// #region PREPARSE
_payload := @rawstring
| message := @rawstring
| Parser.status := "unsupported_format"
// RFC 5424 structured data supports multiple elements and escaped characters.
| case {
    @rawstring = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?1 (?<Vendor.Syslog.timestamp>\S+) (?<Vendor.Syslog.hostname>\S+) (?<Vendor.Syslog.appname>\S+) (?<Vendor.Syslog.procid>\S+) (?<Vendor.Syslog.msgid>\S+) (?:-|(?:\[(?:[^\]\\]|\\.)*\])+)[ ](?<_payload>.*)$/;
    // Some relays add an ISO timestamp after a yearless syslog timestamp.
    @rawstring = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?(?<Vendor.Syslog.localtime>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?<Vendor.Syslog.timestamp>\d{4}-\d{2}-\d{2}T\S+) (?<Vendor.Syslog.hostname>\S+) (?<_payload>.*)$/;
    @rawstring = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?(?<Vendor.Syslog.localtime>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?<Vendor.Syslog.hostname>\S+) (?<_payload>.*)$/;
    @rawstring = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?(?<Vendor.Syslog.timestamp>\d{4}-\d{2}-\d{2}T\S+) (?<Vendor.Syslog.hostname>\S+) (?<_payload>.*)$/;
    @rawstring = /^<(?<Vendor.Syslog.priority>\d{1,3})>(?<_payload>CEF:.*)$/;
    *;
}
// Strip a syslog program tag, or a multiword UniFi site name, only before CEF.
| case {
    _payload = /^CEF:/;
    _payload = /^[^\r\n]*? (?<_payload>CEF:0\|.*)$/;
    *;
}
| case {
    // Older OS exports omit the CEF name field. Insert an empty name solely
    // for parseCEF; the exact original record remains in @rawstring.
    _payload = /^CEF:0\|Ubiquiti\|UniFi OS\|(?<_osVersion>[^|]+)\|(?<_osCode>[^|]+)\|(?<_osSeverity>[^|]+)\|(?<_osExtension>(?:[A-Za-z0-9_]+=.*)?)$/
        | format("CEF:0|Ubiquiti|UniFi OS|%s|%s||%s|%s", field=[_osVersion, _osCode, _osSeverity, _osExtension], as=_cef)
        | case {
            parseCEF(field=_cef, headerprefix="Vendor.Cef.", prefix="Vendor.", labelprefix="Vendor.CefLabel.", keeplabels=true)
                | @error != *
                | Vendor.Cef.device.product = "UniFi OS"
                | Parser.status := "parsed"
                | Vendor.Cef.header_variant := "short_os";
            * | Parser.status := "invalid_cef";
        };
    _payload = /^CEF:0\|Ubiquiti\|UniFi (?:Network|Protect|OS)\|/
        | case {
            parseCEF(field=_payload, headerprefix="Vendor.Cef.", prefix="Vendor.", labelprefix="Vendor.CefLabel.", keeplabels=true)
                | @error != *
                | Vendor.Cef.device.product = *
                | Parser.status := "parsed";
            * | Parser.status := "invalid_cef";
        };
    _payload = /^CEF:/ | Parser.status := "unsupported_cef";
    *;
}
// #endregion

// #region METADATA
| ecs.version := "9.5.0"
| Cps.version := "1.2.0"
| Parser.version := "1.0.1"
| Vendor := "ubiquiti"
| event.module := "unifi"
| event.dataset := "unifi.unknown"
| event.kind := "event"
| case {
    Parser.status = "parsed"
        | case {
            Vendor.Cef.device.product = "UniFi Network" | event.dataset := "unifi.network";
            Vendor.Cef.device.product = "UniFi Protect" | event.dataset := "unifi.protect";
            Vendor.Cef.device.product = "UniFi OS" | event.dataset := "unifi.os";
            *;
        };
    *;
}
// #endregion

// #region NORMALIZATION
| observer.vendor := "ubiquiti"
| observer.product := Vendor.Cef.device.product
| observer.version := Vendor.Cef.device.version
| coalesce([Vendor.UNIFIhost, Vendor.Syslog.hostname], as=observer.name)
// A console display name is not necessarily a DNS hostname.
| event.code := Vendor.Cef.event_class_id
| coalesce([Vendor.msg, Vendor.Cef.name, _payload], as=message)
| coalesce([Vendor.act, Vendor.Cef.name, Vendor.Cef.event_class_id], as=event.action)
| event.reason := Vendor.reason
| log.level := Vendor.Cef.severity
// Verified UniFi OS 6.0.17 config-change format: actor and source IP are
// present only in msg. Restrict extraction to this exact event name and
// anchored message template. Structured CEF identity/address fields win.
| case {
    event.dataset = "unifi.os" AND Vendor.Cef.name = "Admin Made Config Changes"
        | case {
            Vendor.msg = /^(?<_configActor>.+?) changed .+ setting from .+\. Source IP: (?<_configSource>[0-9A-Fa-f:.]+)\s*$/;
            *;
        };
    *;
}
// CEF 0-3 = informational/low, 4-6 = medium, 7-8 = high, 9-10 = critical.
// Use CPS bucket midpoints; do not linearly multiply the CEF value by ten.
| case {
    Vendor.Cef.severity = /^(?:0|1)$/ | event.severity := 10;
    Vendor.Cef.severity = /^(?:2|3|Low|low)$/ | event.severity := 30;
    Vendor.Cef.severity = /^(?:4|5|6|Medium|medium)$/ | event.severity := 50;
    Vendor.Cef.severity = /^(?:7|8|High|high)$/ | event.severity := 70;
    Vendor.Cef.severity = /^(?:9|10|Very-High|very-high)$/ | event.severity := 90;
    *;
}
// CEF src/dst take precedence over UniFi client/device fields. Do not infer
// a destination from the console or AP that merely observed a client event.
| coalesce([Vendor.src, _configSource, Vendor.UNIFIclientIp, Vendor.UNIFIclientIP], as=source.address)
| coalesce([Vendor.dst], as=destination.address)
| lower(source.address)
| lower(destination.address)
| case {
    cidr(source.address, subnet=["0.0.0.0/0", "::/0"]) | source.ip := source.address;
    *;
}
| case {
    cidr(destination.address, subnet=["0.0.0.0/0", "::/0"]) | destination.ip := destination.address;
    *;
}
| case {
    Vendor.spt = /^\d{1,5}$/ | Vendor.spt >= 0 | Vendor.spt <= 65535 | source.port := Vendor.spt;
    *;
}
| case {
    Vendor.dpt = /^\d{1,5}$/ | Vendor.dpt >= 0 | Vendor.dpt <= 65535 | destination.port := Vendor.dpt;
    *;
}
| coalesce([Vendor.suser, Vendor.UNIFIadmin, _configActor], as=user.name)
| source.user.name := Vendor.suser
| destination.user.name := Vendor.duser
| case {
    cidr(Vendor.sourceTranslatedAddress, subnet=["0.0.0.0/0", "::/0"]) | source.nat.ip := Vendor.sourceTranslatedAddress;
    *;
}
| case {
    cidr(Vendor.destinationTranslatedAddress, subnet=["0.0.0.0/0", "::/0"]) | destination.nat.ip := Vendor.destinationTranslatedAddress;
    *;
}
| coalesce([Vendor.smac, Vendor.UNIFIclientMac], as=source.mac)
| destination.mac := Vendor.dmac
| replace(":", with="-", field=source.mac, as=source.mac)
| replace(":", with="-", field=destination.mac, as=destination.mac)
| upper(source.mac)
| upper(destination.mac)
| coalesce([Vendor.UNIFIclientHostname, Vendor.UNIFIdeviceName], as=host.name)
| case {
    Vendor.UNIFIclientHostname = /^[A-Za-z0-9][A-Za-z0-9.-]*$/ | host.hostname := Vendor.UNIFIclientHostname | lower(host.hostname);
    *;
}
| coalesce([Vendor.UNIFIclientIp, Vendor.UNIFIclientIP, Vendor.UNIFIdeviceIp], as=_hostIp)
| case {
    cidr(_hostIp, subnet=["0.0.0.0/0", "::/0"]) | array:append("host.ip[]", values=[_hostIp]);
    *;
}
| coalesce([Vendor.UNIFIclientMac, Vendor.UNIFIdeviceMac], as=_hostMac)
| case {
    _hostMac = /(?i)^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/
        | replace(":", with="-", field=_hostMac, as=_hostMac)
        | upper(_hostMac)
        | array:append("host.mac[]", values=[_hostMac]);
    *;
}
| network.transport := Vendor.proto
| lower(network.transport)
| case {
    network.transport = "6" | network.transport := "tcp" | network.iana_number := "6";
    network.transport = "17" | network.transport := "udp" | network.iana_number := "17";
    network.transport = "1" | network.transport := "icmp" | network.iana_number := "1";
    network.transport = "58" | network.transport := "ipv6-icmp" | network.iana_number := "58";
    network.transport = "tcp" | network.iana_number := "6";
    network.transport = "udp" | network.iana_number := "17";
    network.transport = "icmp" | network.iana_number := "1";
    *;
}
| rule.name := Vendor.UNIFIruleName
| rule.id := Vendor.UNIFIruleId
| observer.ingress.interface.name := Vendor.deviceInboundInterface
| observer.egress.interface.name := Vendor.deviceOutboundInterface
| case {
    Vendor.UNIFInetworkVlan = /^\d{1,4}$/ | Vendor.UNIFInetworkVlan <= 4094 | network.vlan.id := Vendor.UNIFInetworkVlan;
    *;
}

// Timestamp precedence: UniFi UTC event time, CEF rt, syslog ISO, local syslog.
// A failed candidate must not prevent trying the next candidate. Parse to a
// temporary field first so that the collector timestamp remains a fallback.
| case {
    Vendor.UNIFIutcTime = * | parseTimestamp(field=Vendor.UNIFIutcTime, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "UNIFIutcTime";
    *;
}
| case {
    _eventTime = *;
    Vendor.rt = /^\d{13}$/ | parseTimestamp("millis", field=Vendor.rt, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "rt";
    Vendor.rt = * | parseTimestamp(field=Vendor.rt, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "rt";
    *;
}
| case {
    _eventTime = *;
    Vendor.Syslog.timestamp = * | parseTimestamp(field=Vendor.Syslog.timestamp, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "syslog_iso";
    *;
}
| case {
    _eventTime = *;
    // Configure @timezone on the collector for yearless/local timestamps.
    // LogScale infers the year. No implicit local timezone is assumed here.
    Vendor.Syslog.localtime = * | parseTimestamp("MMM [ ]d HH:mm:ss", field=Vendor.Syslog.localtime, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "syslog_local";
    *;
}
| case {
    _eventTime = * | @timestamp := _eventTime;
    * | Parser.timestamp_source := "collector";
}

// Categorize using the CEF event name and structured keys, never arbitrary msg
// text (which can contain quoted user input). No default success outcome.
| case {
    Parser.status != "parsed" | event.kind := "pipeline_error";
    // UniFi OS's test button checks the configured syslog export. Supply a
    // configuration/info category for the tenant's required-field validation.
    // Keep it an ordinary event, without inferring an actor or outcome.
    event.dataset = "unifi.os" AND Vendor.Cef.name = "Test Syslog"
        | array:append("event.category[]", values=["configuration"])
        | array:append("event.type[]", values=["info"]);
    Vendor.Cef.name = /(?i)(?:login failed|failed login|failed to log in|authentication failed|admin access failed)/
        | array:append("event.category[]", values=["authentication"])
        | array:append("event.type[]", values=["start"])
        | event.outcome := "failure";
    Vendor.Cef.name = /(?i)(?:admin accessed|logged in|login successful|logged out|logout)/
        | array:append("event.category[]", values=["authentication"])
        | case {
            Vendor.Cef.name = /(?i)(?:logged out|logout)/ | array:append("event.type[]", values=["end"]);
            * | array:append("event.type[]", values=["start"]);
        }
        | event.outcome := "success";
    // Limit intrusion alerts to Network: Protect's "detection" category also
    // includes normal camera motion and is not a cyber intrusion indicator.
    event.dataset = "unifi.network" AND (Vendor.UNIFIsubCategory = /(?i)^(?:ips|ids|intrusion|intrusion prevention|threat)$/ OR Vendor.Cef.name = /(?i)(?:intrusion|threat detected|honeypot)/)
        | event.kind := "alert"
        | observer.type := "ids"
        | array:append("event.category[]", values=["intrusion_detection", "network"])
        | case {
            Vendor.Cef.name = /(?i)blocked/ OR Vendor.act = /(?i)^(?:block|blocked|drop|dropped|deny|denied)$/ | array:append("event.type[]", values=["denied"]);
            * | array:append("event.type[]", values=["info"]);
        };
    Vendor.Cef.name = /(?i)(?:blocked by firewall|firewall.*blocked)/
        | observer.type := "firewall"
        | array:append("event.category[]", values=["network"])
        | array:append("event.type[]", values=["denied"]);
    event.dataset = "unifi.network" AND Vendor.act = /(?i)^(?:block|blocked|drop|dropped|deny|denied|allow|allowed|accept|accepted)$/
        | observer.type := "firewall"
        | array:append("event.category[]", values=["network"])
        | case {
            Vendor.act = /(?i)^(?:allow|allowed|accept|accepted)$/ | array:append("event.type[]", values=["allowed"]);
            * | array:append("event.type[]", values=["denied"]);
        };
    Vendor.Cef.name = /(?i)(?:client connected|client disconnected|client roamed)/
        | array:append("event.category[]", values=["network"])
        | case {
            Vendor.Cef.name = /(?i)disconnected/ | array:append("event.type[]", values=["connection", "end"]);
            Vendor.Cef.name = /(?i)roamed/ | array:append("event.type[]", values=["connection", "change"]);
            * | array:append("event.type[]", values=["connection", "start"]);
        };
    Vendor.Cef.name = /(?i)(?:settings? (?:changed|updated)|config(?:uration)? (?:changed|updated|changes)|firmware (?:updated|upgraded))/
        | array:append("event.category[]", values=["configuration"])
        | array:append("event.type[]", values=["change"]);
    event.dataset = "unifi.os" AND Vendor.Cef.event_class_id = "admins" AND Vendor.Cef.header_variant = "short_os"
        // Short OS records have only an "admins" class and free text. Preserve
        // them as IAM info; do not infer a successful login or settings change.
        | array:append("event.category[]", values=["iam"])
        | array:append("event.type[]", values=["info"]);
    * | array:append("event.type[]", values=["info"]);
}
// ECS has no physical video-surveillance category or observer type. Leave
// those fields absent on Protect motion/alarm events instead of inventing one.
// All Network alerts have category + type. Use CPS's default severity only if
// the raw alert does not supply a recognized CEF severity.
| case {
    event.kind = "alert" AND event.severity != * | event.severity := 50;
    *;
}
// #endregion

// #region POST-NORMALIZATION
| array:append("related.ip[]", values=[source.ip, destination.ip])
| array:append("related.user[]", values=[user.name, destination.user.name])
| array:append("related.hosts[]", values=[host.hostname])
| drop([_payload, _cef, _osVersion, _osCode, _osSeverity, _osExtension, _eventTime, _configActor, _configSource, _hostIp, _hostMac])
// #endregion
