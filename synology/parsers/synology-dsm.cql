// Synology DSM Log Center. Targets CPS 1.2.0 / ECS 9.5.0.
// One unwrapped record per input; use a dedicated Synology ingest route.

// #region PREPARSE
// Syslog datagrams can retain LF/CRLF/NUL transport terminators. Strip only
// those trailing characters from a working copy; preserve @rawstring exactly.
replace("[\\r\\n\\x00]+$", with="", field=@rawstring, as=_input, flags="")
| _payload := _input
| Parser.status := "unsupported_format"
// ENVELOPE: preserve RFC 5424 structured data, including escaped brackets.
| case {
    _input = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?1 (?<Vendor.Syslog.timestamp>\S+) (?<Vendor.Syslog.hostname>\S+) (?<Vendor.Syslog.appname>\S+) (?<Vendor.Syslog.procid>\S+) (?<Vendor.Syslog.msgid>\S+) (?<Vendor.Syslog.structured_data>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: |$)(?<_payload>.*)$/ | Parser.status := "envelope_only";
    _input = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?(?<Vendor.Syslog.localtime>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?<Vendor.Syslog.timestamp>\d{4}-\d{2}-\d{2}T\S+) (?<Vendor.Syslog.hostname>\S+) (?<_payload>.*)$/ | Parser.status := "envelope_only";
    _input = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?(?<Vendor.Syslog.localtime>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?<Vendor.Syslog.hostname>\S+) (?<_payload>.*)$/ | Parser.status := "envelope_only";
    _input = /^(?:<(?<Vendor.Syslog.priority>\d{1,3})>)?(?<Vendor.Syslog.timestamp>\d{4}-\d{2}-\d{2}T\S+) (?<Vendor.Syslog.hostname>\S+) (?<_payload>.*)$/ | Parser.status := "envelope_only";
    *;
}
// PROGRAM: DSM BSD exports commonly use "Connection SYSTEM: ..." without
// a colon after the program. RFC 5424 may put that program in APP-NAME.
| case {
    _payload = /^(?<Vendor.Log.type>Connection|System|WinFileService|MacFileService|FileStation|FTP|WebDAV|Backup|StorageManager|CMS)(?:\[(?<Vendor.Log.pid>\d+)\])?(?::[ \t]*|[ \t]+)(?<_payload>.*)$/ | Parser.status := "envelope_only";
    Vendor.Syslog.appname = /^(?:Connection|System|WinFileService|MacFileService|FileStation|FTP|WebDAV|Backup|StorageManager|CMS)$/ | Vendor.Log.type := Vendor.Syslog.appname;
    // Generic program tags are stripped only inside a recognized envelope.
    Parser.status = "envelope_only" AND Vendor.Syslog.appname != *
        | case {
            _payload = /^(?<Vendor.Syslog.appname>[A-Za-z0-9_.-]+)(?:\[(?<Vendor.Syslog.procid>\d+)\])?:[ \t]+(?<_payload>.*)$/;
            *;
        };
    *;
}
| Vendor.Message := _payload
| _body := _payload
// ACTOR: this is the logger's actor, often SYSTEM, not the affected user.
| case {
    Vendor.Log.type = /^(?:Connection|System|Backup|StorageManager|CMS)$/
        | case {
            _body = /^(?<Vendor.Log.actor>[^:\r\n]+):[ \t]+(?<_body>.*)$/;
            *;
        };
    *;
}
// #endregion

// #region METADATA
| ecs.version := "9.5.0"
| Cps.version := "1.2.0"
| Parser.version := "1.2.0"
| Vendor := "synology"
| event.module := "dsm"
| event.dataset := "dsm.unknown"
| event.kind := "event"
| case {
    Vendor.Log.type = "Connection" | event.dataset := "dsm.connection";
    Vendor.Log.type = /^(?:WinFileService|MacFileService|FileStation|FTP|WebDAV)$/ | event.dataset := "dsm.file";
    Vendor.Log.type = "System" | event.dataset := "dsm.system";
    Vendor.Log.type = "Backup" | event.dataset := "dsm.backup";
    Vendor.Log.type = "StorageManager" | event.dataset := "dsm.storage";
    Vendor.Log.type = "CMS" | event.dataset := "dsm.cms";
    *;
}
// #endregion

// #region MESSAGE TEMPLATES
// Exact English templates only. No keyword classification of arbitrary text.
| case {
    _body = /^User \[(?<Vendor.User.name>[^\]]*)\] from \[(?<Vendor.Client.address>[^\]]+)\] failed to log in via \[(?<Vendor.Service.name>[^\]]+)\] due to (?<Vendor.Auth.reason>.+)\.$/
        | Vendor.Template := "auth_failure_reason" | event.action := "login" | event.outcome := "failure";
    _body = /^User \[(?<Vendor.User.name>[^\]]*)\] failed to log in from \[(?<Vendor.Client.address>[^\]]+)\] via \[(?<Vendor.Service.name>[^\]]+)\]\.$/
        | Vendor.Template := "auth_failure_legacy" | event.action := "login" | event.outcome := "failure";
    _body = /^User \[(?<Vendor.User.name>[^\]]+)\] from \[(?<Vendor.Client.address>[^\]]+)\] logged in successfully via \[(?<Vendor.Service.name>[^\]]+)\]\.$/
        | Vendor.Template := "auth_success" | event.action := "login" | event.outcome := "success";
    _body = /^User \[(?<Vendor.User.name>[^\]]+)\] from \[(?<Vendor.Client.address>[^\]]+)\] signed in to \[(?<Vendor.Service.name>[^\]]+)\] successfully via \[(?<Vendor.Auth.method>[^\]]+)\]\.$/
        | Vendor.Template := "auth_signin_success" | event.action := "login" | event.outcome := "success";
    // Passing the first factor does not establish a completed 2FA login.
    _body = /^User \[(?<Vendor.User.name>[^\]]+)\] from \[(?<Vendor.Client.address>[^\]]+)\] has successfully passed the first authentication of 2FA via \[(?<Vendor.Auth.method>[^\]]+)\]\.?$/
        | Vendor.Template := "auth_first_factor_success" | event.action := "authentication-first-factor" | event.outcome := "success";
    _body = /^User \[(?<Vendor.User.name>[^\]]+)\] logged in from \[(?<Vendor.Client.address>[^\]]+)\]\.$/
        | Vendor.Template := "auth_success_legacy" | event.action := "login" | event.outcome := "success";
    _body = /^User \[(?<Vendor.User.name>[^\]]+)\] from \[(?<Vendor.Client.address>[^\]]+)\] logged out(?: via \[(?<Vendor.Service.name>[^\]]+)\])?\.$/
        | Vendor.Template := "auth_logout" | event.action := "logout";
    _body = /^User \[(?<Vendor.User.name>[^\]]+)\] from \[(?<Vendor.Client.address>[^\]]+)\] via \[(?<Vendor.Service.name>[^\]]+)\] accessed (?:the )?shared folder \[(?<Vendor.Share.name>[^\]]+)\]\.$/
        | Vendor.Template := "share_access" | event.action := "share-access";
    _body = /^CIFS client \[(?<Vendor.User.name>[^\]]+)\] from \[(?<Vendor.Client.hostname>[^\[\]]*?)\(IP:(?<Vendor.Client.address>[^)]+)\)\] accessed the shared folder \[(?<Vendor.Share.name>[^\]]+)\]\.$/
        | Vendor.Template := "share_access_cifs" | Vendor.Service.name := "CIFS" | event.action := "share-access";
    // Commas and spaces in paths/users are retained. Anchored labels delimit
    // the fields; this is not a general comma-separated key/value parser.
    _body = /^Event: (?<Vendor.File.operation>[A-Za-z]+), Path: (?<Vendor.File.path>.+), File\/Folder: (?<Vendor.File.kind>File|Folder), Size: (?<Vendor.File.size>[^,]+), User: (?<Vendor.User.name>.+), IP: (?<Vendor.Client.address>[^,\s]+)$/
        | Vendor.Template := "file_operation";
    _body = /(?i)^Test message from Synology Syslog Client(?: from .+)?$/
        | Vendor.Template := "syslog_test" | event.action := "syslog-test";
    *;
}
// #region SYSTEM TEMPLATES
// Recognized DSM System message bodies. A CSV
// contains no wire header: require System program context on these mappings.
| case {
    Vendor.Template = *;
    Vendor.Log.type = "System"
        | case {
            _body = /^Update was complete\.$/
                | Vendor.Template := "system_update_complete";
            _body = /^System successfully registered \[(?<Vendor.Ddns.address>[^\]]+)\] to \[(?<Vendor.Ddns.hostname>[^\]]+)\] in DDNS server \[(?<Vendor.Ddns.provider>[^\]]+)\]\.$/
                | Vendor.Template := "system_ddns_registration";
            _body = /^System failed to register \[(?<Vendor.Ddns.address>[^\]]+)\] to \[(?<Vendor.Ddns.hostname>[^\]]+)\] in DDNS server \[(?<Vendor.Ddns.provider>[^\]]+)\] because of \[(?<Vendor.Ddns.reason>[^\]]+)\]\.$/
                | Vendor.Template := "system_ddns_failure";
            _body = /^System successfully (?<Vendor.Ddns.state>enabled|disabled) DDNS update\.$/
                | Vendor.Template := "system_ddns_switch";
            _body = /^System successfully (?<Vendor.Service.state>started|stopped) \[(?<Vendor.Service.name>[^\]]+)\]\.$/
                | Vendor.Template := "system_service_state";
            _body = /^\[(?<Vendor.Service.name>[^\]]+)\] service was (?<Vendor.Service.state>started|stopped)\.$/
                | Vendor.Template := "system_service_legacy";
            _body = /^System failed to (?<Vendor.Service.operation>start|stop) \[(?<Vendor.Service.name>[^\]]+)\]\.$/
                | Vendor.Template := "system_service_failure";
            _body = /^\[(?<Vendor.Process.name>[^\]]+)\] stopped running because the system is out of memory\.$/
                | Vendor.Template := "system_process_oom";
            _body = /^Package \[(?<Vendor.Package.name>[^\]]+)\] has been successfully (?<Vendor.Package.operation>updated|repaired|uninstalled|installed)\.$/
                | Vendor.Template := "system_package_success";
            _body = /^Failed to (?<Vendor.Package.operation>repair|install|update) package \[(?<Vendor.Package.name>[^\]]+)\]\.$/
                | Vendor.Template := "system_package_failure";
            _body = /^\[(?<Vendor.Network.interface>[^\]]+)\] link (?<Vendor.Network.state>up|down)\.$/
                | Vendor.Template := "system_link";
            _body = /^IP address \[(?<Vendor.Network.address>[^\]]+)\] and subnet mask \[(?<Vendor.Network.netmask>[^\]]+)\] were assigned to the DHCP client on \[(?<Vendor.Network.interface>[^\]]+)\]\.$/
                | Vendor.Template := "system_dhcp";
            _body = /^(?<Vendor.System.power_event>System started to boot up|System booted up from an improper shutdown|System started counting down to reboot|System started counting down to shutdown|Server started counting down to shutdown|Server going to Safe Shutdown|Server is on battery|Server back online)\.$/
                | Vendor.Template := "system_power";
            _body = /^User \[(?<Vendor.TargetUser.name>[^\]]+)\] was (?<Vendor.TargetUser.operation>created|disabled|enabled)\.$/
                | Vendor.Template := "system_account_state";
            _body = /^System successfully deleted User \[(?<Vendor.TargetUser.name>[^\]]+)\]\.$/
                | Vendor.Template := "system_account_delete";
            _body = /^User \[(?<Vendor.TargetUser.name>[^\]]+)\] was renamed to \[(?<Vendor.TargetUser.new_name>[^\]]+)\]\.$/
                | Vendor.Template := "system_account_rename";
            _body = /^Password of the user \[(?<Vendor.TargetUser.name>[^\]]+)\] was changed\.$/
                | Vendor.Template := "system_password_change";
            _body = /^User \[(?<Vendor.TargetUser.name>[^\]]+)\] was (?<Vendor.TargetUser.membership>added to|removed from) the group \[(?<Vendor.TargetGroup.name>[^\]]+)\]\.$/
                | Vendor.Template := "system_group_membership";
            _body = /^The app privilege on app \[(?<Vendor.Privilege.app>[^\]]+)\] for (?<Vendor.Privilege.target_type>user|group) \[(?<Vendor.Privilege.target>[^\]]+)\] was set to \[(?<Vendor.Privilege.permission>[^\]]+)\] from \[(?<Vendor.Privilege.scope>[^\]]+)\]\.$/
                | Vendor.Template := "system_app_privilege_set";
            _body = /^The app privilege on app \[(?<Vendor.Privilege.app>[^\]]+)\] for (?<Vendor.Privilege.target_type>user|group) \[(?<Vendor.Privilege.target>[^\]]+)\] was removed\.$/
                | Vendor.Template := "system_app_privilege_remove";
            _body = /^Scheduled Task \[(?<Vendor.Task.name>[^\]]+)\] was (?<Vendor.Task.operation>created|removed|renamed to \[(?<Vendor.Task.new_name>[^\]]+)\])\.$/
                | Vendor.Template := "system_task_state";
            _body = /^(?<Vendor.Share.kind>Normal|Manually-mount encrypted) shared folder \[(?<Vendor.Share.name>[^\]]+)\] was (?<Vendor.Share.operation>created|deleted)\.$/
                | Vendor.Template := "system_share_state";
            _body = /^Storage Pool \[(?<Vendor.Storage.pool>[^\]]+)\] degraded \[(?<Vendor.Storage.detail>[^\]]*)\]\. Please repair it\.$/
                | Vendor.Template := "system_storage_pool_degraded";
            _body = /^Storage Pool \[(?<Vendor.Storage.pool>[^\]]+)\] was crashed\.$/
                | Vendor.Template := "system_storage_pool_crashed";
            _body = /^(?<Vendor.Storage.operation>Read|Write) error at internal disk \[(?<Vendor.Storage.disk>[^\]]+)\], serial \[(?<Vendor.Storage.serial>[^\]]*)\], sector (?<Vendor.Storage.sector>\d+)\.$/
                | Vendor.Template := "system_storage_disk_error";
            _body = /^Space of \[(?<Vendor.Storage.volume>[^\]]+)\] was reaching the limit\.$/
                | Vendor.Template := "system_storage_capacity";
            _body = /^Detected low storage space on Volume \[(?<Vendor.Storage.volume>[^\]]+)\]\.$/
                | Vendor.Template := "system_storage_capacity";
            _body = /^System starts (?<Vendor.Storage.scrub_type>filesystem|data) scrubbing on \[(?<Vendor.Storage.target>[^\]]+)\]\.$/
                | Vendor.Template := "system_scrub_start";
            _body = /^System successfully finished (?<Vendor.Storage.scrub_type>filesystem|data) scrubbing on \[(?<Vendor.Storage.target>[^\]]+)\]\.$/
                | Vendor.Template := "system_scrub_finish";
            _body = /^Filesystem scrubbing on \[(?<Vendor.Storage.target>[^\]]+)\] is canceled\.$/
                | Vendor.Template := "system_scrub_cancel";
            *;
        };
    *;
}
// #endregion SYSTEM TEMPLATES

// #region CMS TEMPLATES
| case {
    Vendor.Template = *;
    Vendor.Log.type = "CMS"
        | case {
            _body = /^Failed to connect to the server\. Switched the connection method from \[(?<Vendor.Cms.previous_method>[^\]]+)\] to \[(?<Vendor.Cms.current_method>[^\]]+)\]\.$/
                | Vendor.Template := "cms_connection_failover"
                | Vendor.Service.name := "CMS";
            *;
        };
    *;
}
// #endregion CMS TEMPLATES

// Matching a body template alone does not prove a vendor program or dataset.
// Assign the semantic dataset for auth/share/file templates even for bare MSG.
| case {
    Vendor.Template = /^auth_/
        | event.dataset := "dsm.connection"
        | array:append("event.category[]", values=["authentication"])
        | case {
            event.action = "logout" | array:append("event.type[]", values=["end"]);
            event.action = "authentication-first-factor" | array:append("event.type[]", values=["info"]);
            * | array:append("event.type[]", values=["start"]);
        };
    Vendor.Template = "cms_connection_failover"
        | event.dataset := "dsm.cms"
        | event.action := "cms-connection-failover"
        | event.outcome := "failure"
        | array:append("event.category[]", values=["network"])
        | array:append("event.type[]", values=["connection"]);
    Vendor.Template = /^share_access/
        | event.dataset := "dsm.connection"
        | array:append("event.category[]", values=["file"])
        | array:append("event.type[]", values=["access"]);
    Vendor.Template = "file_operation"
        | event.dataset := "dsm.file"
        | event.action := Vendor.File.operation | lower(event.action, as=event.action)
        | array:append("event.category[]", values=["file"])
        | case {
            event.action = "create" | array:append("event.type[]", values=["creation"]);
            event.action = "delete" | array:append("event.type[]", values=["deletion"]);
            event.action = /^(?:write|rename|move)$/ | array:append("event.type[]", values=["change"]);
            event.action = /^(?:read|download)$/ | array:append("event.type[]", values=["access"]);
            * | array:append("event.type[]", values=["info"]);
        };
    Vendor.Template = "syslog_test"
        | event.dataset := "dsm.system"
        | array:append("event.category[]", values=["configuration"])
        | array:append("event.type[]", values=["info"]);
    Vendor.Template = /^system_ddns_(?:registration|failure)$/
        | event.action := "ddns-register"
        | array:append("event.category[]", values=["network"])
        | array:append("event.type[]", values=["change"])
        | case {
            Vendor.Template = "system_ddns_registration" | event.outcome := "success";
            * | event.outcome := "failure" | event.reason := Vendor.Ddns.reason;
        };
    Vendor.Template = "system_ddns_switch"
        | format("ddns-%s", field=[Vendor.Ddns.state], as=event.action)
        | event.outcome := "success"
        | array:append("event.category[]", values=["configuration"])
        | array:append("event.type[]", values=["change"]);
    Vendor.Template = /^system_service_/
        | array:append("event.category[]", values=["process"])
        | case {
            Vendor.Template = "system_service_failure"
                | format("service-%s", field=[Vendor.Service.operation], as=event.action)
                | event.outcome := "failure"
                | array:append("event.type[]", values=["info"]);
            Vendor.Service.state = "started"
                | event.action := "service-start" | event.outcome := "success"
                | array:append("event.type[]", values=["start"]);
            * | event.action := "service-stop" | event.outcome := "success"
                | array:append("event.type[]", values=["end"]);
        };
    Vendor.Template = "system_process_oom"
        | event.action := "process-terminated-out-of-memory"
        | array:append("event.category[]", values=["process"])
        | array:append("event.type[]", values=["end"]);
    Vendor.Template = /^system_package_/
        | array:append("event.category[]", values=["package"])
        | case {
            Vendor.Template = "system_package_failure" | event.outcome := "failure";
            * | event.outcome := "success";
        }
        | case {
            Vendor.Package.operation = /^(?:install|installed)$/ | event.action := "package-install" | array:append("event.type[]", values=["installation"]);
            Vendor.Package.operation = "uninstalled" | event.action := "package-uninstall" | array:append("event.type[]", values=["deletion"]);
            Vendor.Package.operation = /^(?:repair|repaired)$/ | event.action := "package-repair" | array:append("event.type[]", values=["change"]);
            * | event.action := "package-update" | array:append("event.type[]", values=["change"]);
        };
    Vendor.Template = "system_update_complete"
        | event.action := "system-update-complete"
        | event.outcome := "success"
        | array:append("event.category[]", values=["package"])
        | array:append("event.type[]", values=["change"]);
    Vendor.Template = "system_link"
        | format("network-link-%s", field=[Vendor.Network.state], as=event.action)
        | array:append("event.category[]", values=["network"])
        | case {
            Vendor.Network.state = "up" | array:append("event.type[]", values=["connection", "start"]);
            * | array:append("event.type[]", values=["connection", "end"]);
        };
    Vendor.Template = "system_dhcp"
        | event.action := "dhcp-address-assigned" | event.outcome := "success"
        | array:append("event.category[]", values=["network", "configuration"])
        | array:append("event.type[]", values=["change"]);
    Vendor.Template = "system_power"
        | event.action := "host-power-status"
        | array:append("event.category[]", values=["host"])
        | case {
            Vendor.System.power_event = "System started to boot up" | event.action := "host-boot" | array:append("event.type[]", values=["start"]);
            Vendor.System.power_event = "System booted up from an improper shutdown" | event.action := "host-boot-after-improper-shutdown" | array:append("event.type[]", values=["start"]);
            * | array:append("event.type[]", values=["info"]);
        };
    Vendor.Template = /^system_(?:account_|password_change|group_membership)/
        | array:append("event.category[]", values=["iam"])
        | event.outcome := "success"
        | case {
            Vendor.TargetUser.operation = "created" | event.action := "user-create" | array:append("event.type[]", values=["user", "creation"]);
            Vendor.Template = "system_account_delete" | event.action := "user-delete" | array:append("event.type[]", values=["user", "deletion"]);
            * | array:append("event.type[]", values=["user", "change"])
                | case {
                    Vendor.Template = "system_account_rename" | event.action := "user-rename";
                    Vendor.Template = "system_password_change" | event.action := "user-password-change";
                    Vendor.TargetUser.membership = "added to" | event.action := "user-added-to-group";
                    Vendor.TargetUser.membership = "removed from" | event.action := "user-removed-from-group";
                    Vendor.TargetUser.operation = "disabled" | event.action := "user-disable";
                    * | event.action := "user-enable";
                };
        };
    Vendor.Template = /^system_app_privilege_/
        | event.action := "app-privilege-change" | event.outcome := "success"
        | array:append("event.category[]", values=["iam"])
        | array:append("event.type[]", values=[Vendor.Privilege.target_type, "change"]);
    Vendor.Template = "system_task_state"
        | event.action := "scheduled-task-change" | event.outcome := "success"
        | array:append("event.category[]", values=["configuration"])
        | case {
            Vendor.Task.operation = "created" | event.action := "scheduled-task-create" | array:append("event.type[]", values=["creation"]);
            Vendor.Task.operation = "removed" | event.action := "scheduled-task-delete" | array:append("event.type[]", values=["deletion"]);
            * | event.action := "scheduled-task-rename" | array:append("event.type[]", values=["change"]);
        };
    Vendor.Template = "system_share_state"
        | event.outcome := "success"
        | array:append("event.category[]", values=["file", "configuration"])
        | case {
            Vendor.Share.operation = "created" | event.action := "shared-folder-create" | array:append("event.type[]", values=["creation"]);
            * | event.action := "shared-folder-delete" | array:append("event.type[]", values=["deletion"]);
        };
    Vendor.Template = /^system_storage_/
        | event.dataset := "dsm.storage"
        | array:append("event.category[]", values=["host"])
        | array:append("event.type[]", values=["info"])
        | case {
            Vendor.Template = "system_storage_pool_degraded" | event.action := "storage-pool-degraded";
            Vendor.Template = "system_storage_pool_crashed" | event.action := "storage-pool-crashed";
            Vendor.Template = "system_storage_disk_error" | event.action := "disk-io-error";
            * | event.action := "storage-capacity-low";
        };
    Vendor.Template = /^system_scrub_/
        | event.dataset := "dsm.storage"
        | array:append("event.category[]", values=["host"])
        | case {
            Vendor.Template = "system_scrub_start" | event.action := "storage-scrub-start" | array:append("event.type[]", values=["start"]);
            Vendor.Template = "system_scrub_finish" | event.action := "storage-scrub-finish" | event.outcome := "success" | array:append("event.type[]", values=["end"]);
            * | event.action := "storage-scrub-cancel" | array:append("event.type[]", values=["end"]);
        };
    * | array:append("event.type[]", values=["info"]);
}
| case {
    Vendor.Template = * | Parser.status := "parsed";
    *;
}
// #endregion

// #region NORMALIZATION
| message := _body
// A NAS is a host, and is the observer of remote client activity. No invented
// ECS observer.type such as "nas" or "storage" is emitted.
| observer.vendor := "synology"
| observer.product := "DSM"
| case {
    Vendor.Syslog.hostname = * AND Vendor.Syslog.hostname != "-" | observer.name := Vendor.Syslog.hostname | host.name := Vendor.Syslog.hostname;
    *;
}
| case {
    cidr(Vendor.Syslog.hostname, subnet=["0.0.0.0/0", "::/0"]) | array:append("host.ip[]", values=[Vendor.Syslog.hostname]);
    Vendor.Syslog.hostname != "-" AND Vendor.Syslog.hostname = /^[A-Za-z0-9][A-Za-z0-9.-]*$/ | lower(Vendor.Syslog.hostname, as=host.hostname);
    *;
}
| case {
    Vendor.User.name = /\S/ | user.name := Vendor.User.name;
    Vendor.Template = /^system_/ AND Vendor.Log.actor = * AND Vendor.Log.actor != "SYSTEM" AND Vendor.Log.actor != "-" | user.name := Vendor.Log.actor;
    *;
}
// On management events, the body names the affected account. The logger's
// actor, if present, remains the root user; do not conflate actor and target.
| user.target.name := Vendor.TargetUser.name
| user.changes.name := Vendor.TargetUser.new_name
| user.target.group.name := Vendor.TargetGroup.name
| case {
    Vendor.Privilege.target_type = "user" | user.target.name := Vendor.Privilege.target;
    Vendor.Privilege.target_type = "group" | group.name := Vendor.Privilege.target;
    *;
}
| process.name := Vendor.Process.name
| package.name := Vendor.Package.name
| case {
    cidr(Vendor.Network.address, subnet=["0.0.0.0/0", "::/0"]) | array:append("host.ip[]", values=[Vendor.Network.address]);
    *;
}
| lower(Vendor.Client.address, as=source.address)
| case {
    cidr(source.address, subnet=["0.0.0.0/0", "::/0"]) | source.ip := source.address;
    *;
}
| coalesce([Vendor.Auth.reason, Vendor.Ddns.reason], as=event.reason)
| service.name := Vendor.Service.name
| case {
    Vendor.Service.name = /(?i)^(?:SMB|CIFS)(?:\(SMB[123]\))?$/ | network.protocol := "smb";
    Vendor.Service.name = "SSH" | network.protocol := "ssh";
    Vendor.Service.name = "FTP" | network.protocol := "ftp";
    Vendor.Service.name = "SFTP" | network.protocol := "sftp";
    Vendor.Service.name = "WebDAV" | network.protocol := "webdav";
    Vendor.Log.type = "WinFileService" | network.protocol := "smb";
    Vendor.Log.type = "MacFileService" | network.protocol := "afp";
    Vendor.Log.type = "FTP" | network.protocol := "ftp";
    Vendor.Log.type = "WebDAV" | network.protocol := "webdav";
    *;
}
// Retain share names without inventing absolute filesystem paths. File sizes
// in KB/MB/GB are rounded vendor display values, not exact byte counters.
| file.path := Vendor.File.path
| case {
    Vendor.File.kind = "Folder" | file.type := "directory";
    Vendor.File.kind = "File" | file.type := "file";
    *;
}
| case {
    Vendor.File.size = /^(?<file.size>\d+) Bytes?$/;
    *;
}
| case {
    Vendor.Syslog.priority = /^\d{1,3}$/ | Vendor.Syslog.priority <= 191
        | log.syslog.priority := Vendor.Syslog.priority
        | math:mod(log.syslog.priority, divisor=8, as=log.syslog.severity.code)
        | case {
            log.syslog.severity.code = 0 | log.level := "emergency";
            log.syslog.severity.code = 1 | log.level := "alert";
            log.syslog.severity.code = 2 | log.level := "critical";
            log.syslog.severity.code = 3 | log.level := "error";
            log.syslog.severity.code = 4 | log.level := "warning";
            log.syslog.severity.code = 5 | log.level := "notice";
            log.syslog.severity.code = 6 | log.level := "info";
            log.syslog.severity.code = 7 | log.level := "debug";
            *;
        };
    *;
}
// Syslog priority is operational severity; it is not a threat confidence score.
// Timestamp fallback keeps the input timestamp if every candidate fails.
| case {
    Vendor.Syslog.timestamp = * | parseTimestamp(field=Vendor.Syslog.timestamp, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "syslog_iso";
    *;
}
| case {
    _eventTime = *;
    // Falcon Log Collector supplies its configured zone separately from
    // @timezone, which may still be the ingest default (Z). Prefer it for BSD.
    Vendor.Syslog.localtime = * AND @collect.timezone = * | parseTimestamp("MMM [ ]d HH:mm:ss", field=Vendor.Syslog.localtime, timezoneField=@collect.timezone, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "syslog_local";
    *;
}
| case {
    _eventTime = *;
    // Supply the NAS timezone via @timezone; year is inferred by LogScale.
    Vendor.Syslog.localtime = * | parseTimestamp("MMM [ ]d HH:mm:ss", field=Vendor.Syslog.localtime, as=_eventTime, addErrors=false) | _eventTime = * | Parser.timestamp_source := "syslog_local";
    *;
}
| case {
    _eventTime = * | @timestamp := _eventTime;
    * | Parser.timestamp_source := "collector";
}
// #endregion

// #region POST-NORMALIZATION
| array:append("related.ip[]", values=[source.ip])
| array:append("related.user[]", values=[user.name, user.target.name, user.changes.name])
| array:append("related.hosts[]", values=[host.hostname])
| drop([_input, _payload, _body, _eventTime])
// #endregion
